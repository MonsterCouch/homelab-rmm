package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/MonsterCouch/homelab-rmm/internal/translog"
)

// defaultLogState is where `log verify` remembers the last head it checked.
const defaultLogState = "log-verify.json"

// logState is the pinned head. Only the size and root hash are kept: the
// signature was checked when the head was pinned, and the next run proves the
// new head extends this one.
type logState struct {
	Size int64  `json:"size"`
	Hash string `json:"hash"`
}

// runLog is the `log` subcommand: an auditor's view of the server's
// transparency log. Both endpoints it uses are public, so it needs no login.
func runLog(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "head":
		fs := flag.NewFlagSet("log head", flag.ExitOnError)
		fs.Usage = usage
		server := fs.String("server", "", "base URL of the server, for example https://rmm.example.com")
		fs.Parse(args[1:])
		if *server == "" {
			fmt.Fprintln(os.Stderr, "--server is required")
			return 2
		}
		h, err := fetchLogHead(http.DefaultClient, *server)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("size %d\nhash %s\nkey %s\n", h.Size, h.Hash, h.Key)
		return 0
	case "verify":
		fs := flag.NewFlagSet("log verify", flag.ExitOnError)
		fs.Usage = usage
		server := fs.String("server", "", "base URL of the server, for example https://rmm.example.com")
		key := fs.String("key", "", "the log's verifier key (homelab-rmm-log+...), obtained out of band")
		state := fs.String("state", defaultLogState, "file that pins the last verified head (default log-verify.json in the current directory)")
		fs.Parse(args[1:])
		if *server == "" || *key == "" {
			fmt.Fprintln(os.Stderr, "--server and --key are required")
			return 2
		}
		line, err := verifyLog(http.DefaultClient, *server, *key, *state)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(line)
		return 0
	}
	usage()
	return 2
}

type logHeadReply struct {
	Size int64  `json:"size"`
	Hash string `json:"hash"`
	Key  string `json:"key"`
	Note string `json:"note"`
}

func getJSON(c *http.Client, u string, out any) error {
	if c.Timeout == 0 {
		cc := *c
		cc.Timeout = 30 * time.Second
		c = &cc
	}
	resp, err := c.Get(u)
	if err != nil {
		return fmt.Errorf("The server could not be reached: %v.", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("The server answered %s to %s.", resp.Status, u)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("The server's answer to %s was not the JSON this tool expects.", u)
	}
	return nil
}

func logURL(server, path string, q url.Values) string {
	u := strings.TrimRight(server, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

func fetchLogHead(c *http.Client, server string) (logHeadReply, error) {
	var h logHeadReply
	err := getJSON(c, logURL(server, "/api/log/head", nil), &h)
	return h, err
}

// verifyLog checks the server's current head with the given key and proves it
// extends the head pinned in stateFile, then pins the new one. The returned
// line is what the command prints on success.
func verifyLog(c *http.Client, server, key, stateFile string) (string, error) {
	h, err := fetchLogHead(c, server)
	if err != nil {
		return "", err
	}
	note, err := base64.StdEncoding.DecodeString(h.Note)
	if err != nil {
		return "", errors.New("The server's signed head was not valid base64.")
	}
	head, err := translog.ParseHead(key, note)
	if err != nil {
		return "", fmt.Errorf("The server's head does not verify against the key you gave, so it is not this log or it was tampered with: %v.", err)
	}

	var old logState
	have := false
	if raw, err := os.ReadFile(stateFile); err == nil {
		if err := json.Unmarshal(raw, &old); err != nil {
			return "", fmt.Errorf("The state file %s is damaged; delete it to start pinning again.", stateFile)
		}
		have = old.Size > 0
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("The state file %s could not be read: %v.", stateFile, err)
	}

	if have {
		oldHash, err := tlog.ParseHash(old.Hash)
		if err != nil {
			return "", fmt.Errorf("The state file %s holds a damaged hash; delete it to start pinning again.", stateFile)
		}
		oldTree := tlog.Tree{N: old.Size, Hash: oldHash}
		switch {
		case head.N < old.Size:
			return "", fmt.Errorf("The log shrank from %d entries to %d, which an append-only log must never do.", old.Size, head.N)
		case head.N == old.Size:
			if head.Hash != oldHash {
				return "", fmt.Errorf("The log has %d entries, as before, but a different head hash: its history was rewritten.", head.N)
			}
		default:
			var cr struct {
				Proof []string `json:"proof"`
			}
			q := url.Values{"from": {strconv.FormatInt(old.Size, 10)}, "to": {strconv.FormatInt(head.N, 10)}}
			if err := getJSON(c, logURL(server, "/api/log/consistency", q), &cr); err != nil {
				return "", err
			}
			proof, err := translog.DecodeProof(cr.Proof)
			if err != nil {
				return "", fmt.Errorf("The server's consistency proof could not be read: %v.", err)
			}
			if err := translog.CheckConsistency(oldTree, head, proof); err != nil {
				return "", fmt.Errorf("The log at %d entries is not an extension of the head pinned at %d entries, so its history was rewritten: %v.", head.N, old.Size, err)
			}
		}
	}

	raw, _ := json.Marshal(logState{Size: head.N, Hash: head.Hash.String()})
	if err := os.WriteFile(stateFile, append(raw, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("The verified head could not be saved to %s: %v.", stateFile, err)
	}
	return fmt.Sprintf("log ok: size %d, head %s", head.N, head.Hash), nil
}
