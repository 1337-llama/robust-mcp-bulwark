// Command ci-summary renders the suite's results.json as a Markdown table for
// the GitHub job summary (spec 001 AC-20). With -compare it exits 3 if two
// results files differ, ignoring the header (AC-22).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
)

type cell struct {
	Scenario, Control, Condition, Revision, Status, Detail string
}

func load(path string) ([]cell, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r struct{ Cells []cell }
	return r.Cells, json.Unmarshal(b, &r)
}

var icon = map[string]string{"pass": "✅ pass", "fail": "❌ fail", "pending": "⏳ pending", "timeout": "❌ timeout"}

func render(w io.Writer, cells []cell) {
	type key struct{ s, c, r string }
	rows := map[key]map[string]string{}
	for _, c := range cells {
		k := key{c.Scenario, c.Control, c.Revision}
		if rows[k] == nil {
			rows[k] = map[string]string{}
		}
		rows[k][c.Condition] = icon[c.Status]
	}
	keys := make([]key, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].s+keys[i].c+keys[i].r < keys[j].s+keys[j].c+keys[j].r
	})
	fmt.Fprintln(w, "| Scenario | Control | Revision | Without Bulwark | warn | enforce |")
	fmt.Fprintln(w, "|---|---|---|---|---|---|")
	for _, k := range keys {
		r := rows[k]
		fmt.Fprintf(w, "| %s | `%s` | %s | %s | %s | %s |\n", k.s, k.c, k.r, r["none"], r["warn"], r["enforce"])
	}
}

func main() {
	args := os.Args[1:]
	if len(args) == 3 && args[0] == "-compare" {
		a, errA := load(args[1])
		b, errB := load(args[2])
		if errA != nil || errB != nil {
			fmt.Fprintln(os.Stderr, "ci-summary:", errA, errB)
			os.Exit(1)
		}
		if !reflect.DeepEqual(a, b) {
			fmt.Fprintln(os.Stderr, "ci-summary: the two suite runs differ (NFR-008)")
			os.Exit(3)
		}
		return
	}
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: ci-summary results.json | ci-summary -compare a.json b.json")
		os.Exit(2)
	}
	cells, err := load(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "ci-summary:", err)
		os.Exit(1)
	}
	render(os.Stdout, cells)
	for _, c := range cells {
		if c.Status == "fail" || c.Status == "timeout" {
			fmt.Printf("\n**%s `%s` %s %s:** %s\n", c.Scenario, c.Control, c.Condition, c.Revision, strings.TrimSpace(c.Detail))
		}
	}
}
