package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// The first-run setup code is minted in memory by the running server and is
// never stored, so a second process cannot read it out of the database: the
// only durable copy is the `setup_code=` attribute of the FIRST RUN warning in
// server.log. That file is the thing an operator cannot find when the server
// runs as a Windows service, where stderr goes nowhere and the banner the
// server prints to the console is never seen by anybody. The symptom is a
// console that asks for a code the operator never configured, which reads as a
// broken install rather than a working one.

// runSetupCode informs the user that a setup code is no longer required.
func runSetupCode(args []string) int {
	fmt.Println("Homelab RMM does not require a setup code. Open the web console directly to create the administrator account.")
	return 0
}

// latestSetupCode returns the code from the most recent FIRST RUN line in the
// log, or "" when the log holds none. The last match wins because a code is
// minted on every start that finds no users, so an old one further up the file
// is already dead.
//
// A missing log is not an error: a server that has never started has no log,
// and the caller's "restart and look again" advice is the right answer for
// both that and a log without a code.
func latestSetupCode(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()

	const attr = "setup_code="
	code := ""
	sc := bufio.NewScanner(f)
	// The default 64 KiB limit is generous for a log line, but a single
	// oversized one would otherwise abort the scan and lose a code below it.
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		i := strings.LastIndex(line, attr)
		if i < 0 {
			continue
		}
		// slog's text handler quotes a value only when it needs to, so accept
		// both forms and stop at the first space of an unquoted one.
		v := strings.TrimPrefix(line[i+len(attr):], `"`)
		v = strings.TrimRight(v, `"`)
		if j := strings.IndexAny(v, " \t"); j >= 0 {
			v = v[:j]
		}
		if v = strings.TrimSpace(v); v != "" {
			code = v
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return code, nil
}
