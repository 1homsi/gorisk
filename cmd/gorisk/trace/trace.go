package trace

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type event struct {
	kind   string
	detail string
}

func Run(args []string) int {
	fs := flag.NewFlagSet("trace", flag.ExitOnError)
	timeout := fs.Duration("timeout", 0, "stop tracing after duration (e.g. 10s); 0 = run to completion")
	jsonOut := fs.Bool("json", false, "JSON output")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gorisk trace [--timeout 10s] [--json] <package> [args...]")
		return 2
	}

	bin, err := buildBinary(rest[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		return 2
	}
	defer os.Remove(bin)

	tracer, err := detectTracer()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	events, err := runWithTracer(tracer, bin, rest[1:], *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trace:", err)
		return 2
	}

	if *jsonOut {
		printJSON(events)
	} else {
		printText(events)
	}
	return 0
}

func buildBinary(pkg string) (string, error) {
	f, err := os.CreateTemp("", "gorisk-trace-*")
	if err != nil {
		return "", err
	}
	f.Close()

	bin := f.Name()
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	cmd := exec.Command("go", "build", "-o", bin, pkg)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Remove(bin)
		return "", fmt.Errorf("go build %s: %w", pkg, err)
	}
	return bin, nil
}

func detectTracer() (string, error) {
	switch runtime.GOOS {
	case "linux":
		if path, err := exec.LookPath("strace"); err == nil {
			return path, nil
		}
		return "", fmt.Errorf("strace not found; install with: apt install strace")
	case "darwin":
		if path, err := exec.LookPath("dtrace"); err == nil {
			return path, nil
		}
		return "", fmt.Errorf("dtrace not available; run as root or disable SIP")
	default:
		return "", fmt.Errorf("runtime tracing not supported on %s", runtime.GOOS)
	}
}

func runWithTracer(tracer, bin string, binArgs []string, dur time.Duration) ([]event, error) {
	tmpOut, err := os.CreateTemp("", "gorisk-strace-*")
	if err != nil {
		return nil, err
	}
	tmpOut.Close()
	defer os.Remove(tmpOut.Name())

	var ctx context.Context
	var cancel context.CancelFunc
	if dur > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), dur)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	var cmd *exec.Cmd
	switch filepath.Base(tracer) {
	case "strace":
		a := []string{"-f", "-e", "trace=openat,open,connect,execve", "-o", tmpOut.Name(), "--", bin}
		a = append(a, binArgs...)
		cmd = exec.CommandContext(ctx, tracer, a...)
	case "dtrace":
		script := `syscall::open*:entry { printf("fs %s\n", copyinstr(arg0)); }
syscall::connect:entry { printf("net connect\n"); }
syscall::execve:entry  { printf("exec %s\n", copyinstr(arg0)); }`
		a := []string{"-n", script, "-c", bin + " " + strings.Join(binArgs, " ")}
		cmd = exec.CommandContext(ctx, "sudo", append([]string{tracer}, a...)...)
	default:
		return nil, fmt.Errorf("unsupported tracer: %s", tracer)
	}

	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Start()
	cmd.Wait()

	data, err := os.ReadFile(tmpOut.Name())
	if err != nil {
		return nil, err
	}

	if filepath.Base(tracer) == "strace" {
		return parseStrace(string(data)), nil
	}
	return parseDtrace(string(data)), nil
}

func parseStrace(out string) []event {
	seen := make(map[string]bool)
	var events []event
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		call, rest, ok := strings.Cut(line, "(")
		if !ok {
			continue
		}
		call = strings.TrimSpace(call)
		if i := strings.LastIndex(call, " "); i >= 0 {
			call = call[i+1:]
		}
		switch call {
		case "openat", "open":
			detail := firstQuoted(rest)
			if detail == "" || strings.HasPrefix(detail, "/proc") || strings.HasPrefix(detail, "/sys") {
				continue
			}
			if key := "fs:" + detail; !seen[key] {
				seen[key] = true
				events = append(events, event{"filesystem", detail})
			}
		case "connect":
			if !strings.Contains(rest, "AF_INET") {
				continue
			}
			detail := netDetail(rest)
			if key := "net:" + detail; !seen[key] {
				seen[key] = true
				events = append(events, event{"network", detail})
			}
		case "execve":
			detail := firstQuoted(rest)
			if key := "exec:" + detail; !seen[key] {
				seen[key] = true
				events = append(events, event{"subprocess", detail})
			}
		}
	}
	return events
}

func parseDtrace(out string) []event {
	seen := make(map[string]bool)
	var events []event
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		kind, detail, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		var k string
		switch kind {
		case "fs":
			k = "filesystem"
		case "net":
			k = "network"
		case "exec":
			k = "subprocess"
		default:
			continue
		}
		if key := k + ":" + detail; !seen[key] {
			seen[key] = true
			events = append(events, event{k, detail})
		}
	}
	return events
}

func firstQuoted(s string) string {
	after, ok := strings.CutPrefix(s, `"`)
	if !ok {
		if _, after2, ok2 := strings.Cut(s, `"`); ok2 {
			after = after2
		} else {
			return ""
		}
	}
	val, _, ok := strings.Cut(after, `"`)
	if !ok {
		return ""
	}
	return val
}

func netDetail(s string) string {
	if _, after, ok := strings.Cut(s, "sin_addr=inet_addr("); ok {
		if addr, _, ok2 := strings.Cut(after, ")"); ok2 {
			if _, portStr, ok3 := strings.Cut(s, "sin_port=htons("); ok3 {
				if port, _, ok4 := strings.Cut(portStr, ")"); ok4 {
					return addr + ":" + port
				}
			}
			return addr
		}
	}
	return "unknown"
}

func printText(events []event) {
	const (
		red    = "\033[31m"
		yellow = "\033[33m"
		cyan   = "\033[36m"
		bold   = "\033[1m"
		reset  = "\033[0m"
	)

	byKind := make(map[string][]string)
	for _, e := range events {
		byKind[e.kind] = append(byKind[e.kind], e.detail)
	}

	for _, s := range []struct{ kind, label, col string }{
		{"filesystem", "Filesystem Access", yellow},
		{"network", "Network Calls", red},
		{"subprocess", "Subprocess Execution", cyan},
	} {
		items := byKind[s.kind]
		fmt.Printf("%s%s%s  (%d)\n", bold, s.label, reset, len(items))
		for _, item := range items {
			fmt.Printf("  %s%s%s\n", s.col, item, reset)
		}
		fmt.Println()
	}

	if len(events) == 0 {
		fmt.Println("no syscall events captured")
	}
}

func printJSON(events []event) {
	fmt.Println("[")
	for i, e := range events {
		comma := ","
		if i == len(events)-1 {
			comma = ""
		}
		fmt.Printf("  {\"kind\":%q,\"detail\":%q}%s\n", e.kind, e.detail, comma)
	}
	fmt.Println("]")
}
