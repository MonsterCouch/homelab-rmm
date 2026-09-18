package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/server"
)

// The first-run setup code is minted in memory by the running server and is
// never stored, so a second process cannot read it out of the database: the
// only durable copy is the `setup_code=` attribute of the FIRST RUN warning in
// server.log. That file is the thing an operator cannot find when the server
// runs as a Windows service, where stderr goes nowhere and the banner the
// server prints to the console is never seen by anybody. The symptom is a
// console that asks for a code the operator never configured, which reads as a
// broken install rather than a working one.

// runSetupCode prints the one-time first-run setup code, or explains why there
// is not one.
func runSetupCode(args []string) int {
	fs := flag.NewFlagSet("setup-code", flag.ExitOnError)
	fs.Usage = usage
	data := fs.String("data", server.DefaultDataDir(), "data directory holding server.log")
	fs.Parse(args)
	cfg := server.Config{DataDir: *data, Listen: ":8443", Insecure: true}.FromEnv()

	// Once the first administrator exists the code is spent and the form stops
	// asking for it, so printing a stale one would send the operator in a
	// circle. A database this cannot open is not fatal: the log is still the
	// answer, so the user count is reported only when it can be read.
	//
	// The console's address comes from the same place, because the saved
	// setting is authoritative and the flag is only a first-run fallback - so
	// the URL printed below is the one agents were actually told to use.
	consoleURL := cfg.PublicURL
	if db, err := server.OpenDatabase(cfg); err == nil {
		n := db.UserCount()
		if u := db.Setting("public_url", ""); u != "" {
			consoleURL = u
		}
		db.Close()
		if n > 0 {
			fmt.Printf("already set up: this server has %d user account(s), so the setup code is spent.\n"+
				"Locked out? Reset a password with:  rmm-server user passwd --username <name>\n", n)
			return 0
		}
	}

	path := filepath.Join(cfg.DataDir, "server.log")
	code, err := latestSetupCode(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", path, err)
		return 1
	}
	if code == "" {
		fmt.Fprintf(os.Stderr, "no setup code found in %s.\n"+
			"A fresh code is minted on every start that finds no users, so restart the\n"+
			"server and run this again:  rmm-server restart\n", path)
		return 1
	}
	// The same banner the server prints, so the two are recognisably the thing
	// the console is asking for.
	fmt.Printf("\n==== FIRST-RUN SETUP CODE: %s ====\n\n", code)
	if consoleURL != "" {
		fmt.Printf("Enter it in the Setup code field at %s\n", consoleURL)
	} else {
		fmt.Println("Enter it in the Setup code field on the console's first-run form.")
	}
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
