package svc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// UinputRuleName is the udev rule file `install` writes on Linux.
const UinputRuleName = "70-homelab-rmm-uinput.rules"

// UinputRule is the rule's exact content. On Ubuntu /dev/uinput is root:root
// 0600, so the desktop helper (which runs as the session user) could not
// inject input on Wayland. GROUP/MODE make it group-accessible and the
// "uaccess" tag makes logind give the active seat user an ACL on it, so no
// group membership or re-login is needed.
const UinputRule = `KERNEL=="uinput", GROUP="input", MODE="0660", TAG+="uaccess"` + "\n"

// uinputManual is the instruction every warning ends with.
const uinputManual = "to do it by hand: write " + UinputRule + "to /etc/udev/rules.d/" + UinputRuleName +
	", then run `udevadm control --reload-rules` and `udevadm trigger --name-match=uinput`"

const uinputToolTimeout = 10 * time.Second

// Seams; tests replace them so nothing touches /etc or runs udevadm.
var (
	uinputGOOS     = runtime.GOOS
	uinputRulesDir = "/etc/udev/rules.d"
	uinputDevPath  = "/dev/uinput"
	uinputRunTool  = runUinputTool
)

// runUinputTool resolves name through PATH and runs it by absolute path with a
// short timeout.
func runUinputTool(name string, args ...string) error {
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), uinputToolTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		if msg := string(bytes.TrimSpace(out)); msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

// InstallUinputRule makes /dev/uinput usable by the session user. It is a
// no-op off Linux and never fails the install: it returns warnings for the
// caller to print.
func InstallUinputRule() []string {
	if uinputGOOS != "linux" {
		return nil
	}
	var warns []string
	warn := func(format string, a ...any) {
		warns = append(warns, "warning: "+fmt.Sprintf(format, a...)+"; "+uinputManual)
	}
	if _, err := os.Stat(uinputDevPath); errors.Is(err, os.ErrNotExist) {
		if err := uinputRunTool("modprobe", "uinput"); err != nil {
			warn("%s does not exist and `modprobe uinput` failed: %v", uinputDevPath, err)
		}
	}
	path := filepath.Join(uinputRulesDir, UinputRuleName)
	if cur, err := os.ReadFile(path); err != nil || string(cur) != UinputRule {
		if err := os.MkdirAll(uinputRulesDir, 0o755); err != nil {
			warn("cannot create %s: %v", uinputRulesDir, err)
			return warns
		}
		if err := os.WriteFile(path, []byte(UinputRule), 0o644); err != nil {
			warn("cannot write %s: %v", path, err)
			return warns
		}
	}
	if err := uinputRunTool("udevadm", "control", "--reload-rules"); err != nil {
		warn("udevadm control --reload-rules failed: %v", err)
	}
	if err := uinputRunTool("udevadm", "trigger", "--name-match=uinput"); err != nil {
		warn("udevadm trigger --name-match=uinput failed: %v", err)
	}
	return warns
}

// RemoveUinputRule undoes InstallUinputRule: it deletes the rule file and
// reloads the rules. A missing file is not an error. No-op off Linux.
func RemoveUinputRule() []string {
	if uinputGOOS != "linux" {
		return nil
	}
	path := filepath.Join(uinputRulesDir, UinputRuleName)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return []string{fmt.Sprintf("warning: cannot remove %s: %v", path, err)}
	}
	if err := uinputRunTool("udevadm", "control", "--reload-rules"); err != nil {
		return []string{fmt.Sprintf("warning: removed %s but `udevadm control --reload-rules` failed: %v", path, err)}
	}
	return nil
}
