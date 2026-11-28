// Command fakeupstream is a scripted MCP server stand-in for the proxy tests
// (spec 002 T12). FAKE selects behaviors, comma-separated:
//
//	stderr      write bytes to stderr at start
//	exit=N      exit with code N after the first request
//	ignoreterm  ignore SIGTERM and keep running after stdin closes
//	grandchild  start a long-running grandchild and print its PID to stderr
//	unknownid   answer the first request with an unknown id first
//	malformed   answer the first request with a truncated line
//	serverreq   send a roots/list request at start
//	mute        never answer
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
)

func main() {
	opts := map[string]string{}
	for _, o := range strings.Split(os.Getenv("FAKE"), ",") {
		k, v, _ := strings.Cut(o, "=")
		opts[k] = v
	}
	if _, ok := opts["stderr"]; ok {
		os.Stderr.Write([]byte("fake-stderr \xff\x00 raw\n"))
	}
	if _, ok := opts["ignoreterm"]; ok {
		signal.Ignore(syscall.SIGTERM)
	}
	if _, ok := opts["grandchild"]; ok {
		c := exec.Command("sleep", "60")
		c.Start()
		fmt.Fprintf(os.Stderr, "grandchild=%d\n", c.Process.Pid)
	}
	out := bufio.NewWriter(os.Stdout)
	send := func(s string) { out.WriteString(s + "\n"); out.Flush() }
	if _, ok := opts["serverreq"]; ok {
		send(`{"jsonrpc":"2.0","id":"s1","method":"roots/list"}`)
	}
	sc := bufio.NewScanner(os.Stdin)
	first := true
	for sc.Scan() {
		m, err := jsonrpc.Parse(sc.Bytes(), 64)
		if err != nil || m.Kind != jsonrpc.Request {
			continue
		}
		if _, ok := opts["mute"]; ok {
			continue
		}
		id := string(jsonrpc.Serialize(m.ID))
		if first {
			if _, ok := opts["unknownid"]; ok {
				send(`{"jsonrpc":"2.0","id":999,"result":{}}`)
			}
			if _, ok := opts["malformed"]; ok {
				send(`{"jsonrpc":"2.0","id":` + id + `,"result":`)
				first = false
				continue
			}
		}
		params := "null"
		if p := m.Root.Get("params"); p != nil {
			params = string(jsonrpc.Serialize(p))
		}
		send(`{"jsonrpc":"2.0","id":` + id + `,"result":{"echo":` + params + `}}`)
		if code, ok := opts["exit"]; ok && first {
			var n int
			fmt.Sscan(code, &n)
			os.Exit(n)
		}
		first = false
	}
	if _, ok := opts["ignoreterm"]; ok {
		time.Sleep(time.Minute)
	}
}
