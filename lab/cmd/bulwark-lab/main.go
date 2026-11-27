// LAB ONLY: bulwark-lab runs the harmless attack-lab MCP servers for the test
// suite. It refuses to start unless BULWARK_LAB=1 (spec 001 AC-5).
package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/1337-llama/robust-mcp-bulwark/lab/servers/l01notes"
	"github.com/1337-llama/robust-mcp-bulwark/lab/servers/l02weather"
	"github.com/1337-llama/robust-mcp-bulwark/lab/servers/l03mail"
	"github.com/1337-llama/robust-mcp-bulwark/lab/servers/l05translate"
	"github.com/1337-llama/robust-mcp-bulwark/lab/servers/l06calc"
)

// servers maps a lab server name to its entry point.
var servers = map[string]func(stdin io.Reader, stdout io.Writer) error{
	"l01-notes":     l01notes.Serve,
	"l02-weather":   l02weather.Serve,
	"l03-mail":      l03mail.Serve,
	"l05-translate": l05translate.Serve,
	"l06-calc":      l06calc.Serve,
}

func main() { os.Exit(run(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if getenv("BULWARK_LAB") != "1" {
		fmt.Fprintln(stderr, "bulwark-lab: refusing to start: set BULWARK_LAB=1 (attack lab, tests only)")
		return 2
	}
	fmt.Fprintln(stderr, "LAB ONLY: intentionally malicious, harmless test MCP server. Do not connect to real agents or data.")
	if len(args) != 1 {
		fmt.Fprintf(stderr, "usage: bulwark-lab <server>  (%s)\n", names())
		return 2
	}
	serve, ok := servers[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "bulwark-lab: unknown lab server %q (%s)\n", args[0], names())
		return 2
	}
	if err := serve(stdin, stdout); err != nil {
		fmt.Fprintln(stderr, "bulwark-lab:", err)
		return 1
	}
	return 0
}

func names() string {
	n := make([]string, 0, len(servers))
	for k := range servers {
		n = append(n, k)
	}
	sort.Strings(n)
	return strings.Join(n, ", ")
}
