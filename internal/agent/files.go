package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const fsMaxRead = 8 << 20

// fsMaxEntries bounds one directory listing. The whole listing is serialised
// into a single agent frame, and the server drops the device's socket when a
// frame exceeds its read limit - so an unbounded listing of a directory with
// tens of thousands of entries took the device offline, from any account that
// could open the file browser. Truncating is the lesser failure, and the
// result says so rather than silently showing a short list.
const fsMaxEntries = 20000

// fsOSPath is the name to hand to the operating system.
//
// Windows strips trailing dots and spaces while normalising an ordinary path,
// so "report.txt." addresses a *different* file from the one the operator saw
// in the listing: a delete quietly missed, and a write landed on the
// neighbouring name and overwrote it. The extended-length form turns that
// normalisation off, so every call acts on exactly the name we were given.
// Drive-letter paths only: a UNC path is already prefixed differently and an
// extended-length prefix on a relative path is invalid.
func fsOSPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	if p == "" || strings.HasPrefix(p, `\\`) || !filepath.IsAbs(p) {
		return p
	}
	return `\\?\` + filepath.Clean(p)
}

// fsNorm is a path in the one shape the comparisons below use: lower case on
// Windows (its filesystem is case-insensitive), forward slashes, no trailing
// separator.
func fsNorm(p string) string {
	s := filepath.ToSlash(filepath.Clean(p))
	if runtime.GOOS == "windows" {
		s = strings.ToLower(s)
	}
	return strings.TrimSuffix(s, "/")
}

// fsUnder reports whether p is dir itself or anything beneath it.
func fsUnder(p, dir string) bool {
	a, b := fsNorm(p), fsNorm(dir)
	return a == b || strings.HasPrefix(a, b+"/")
}

// fsIsRoot reports whether p is a filesystem root ("/", "C:\"), which nothing
// here may delete or rename.
func fsIsRoot(p string) bool {
	c := filepath.Clean(p)
	return c == "/" || c == string(filepath.Separator) || c == filepath.VolumeName(c)+string(filepath.Separator) || c == filepath.VolumeName(c)+"/"
}

// fsCheckPath is the agent-side backstop for every file-browser operation.
//
// The server applies its own role gate, but the agent is the only side that
// knows where its own configuration actually lives, and it is the side that
// would do the damage. Two things are refused outright here:
//
//   - A path that is not absolute. It would be resolved against the agent's
//     working directory, which for a Windows service is C:\Windows\System32 -
//     so a delete of "..", "C:" or a bare name operated there.
//   - Anything inside the agent's own configuration directory, which holds the
//     device key and the enrollment token. Reads are refused as well as writes:
//     downloading agent.json is what hands over the device's identity.
func fsCheckPath(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", errors.New("a path is required")
	}
	if strings.ContainsAny(p, "\x00\n\r") {
		return "", errors.New("a path must not contain control characters")
	}
	if len(p) > 4096 {
		return "", errors.New("a path must be shorter than 4096 characters")
	}
	clean := filepath.Clean(p)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("%q is not an absolute path: a relative path would be resolved against the agent's own working directory", p)
	}
	if fsUnder(clean, ConfigDir()) {
		return "", errors.New("the agent's own configuration directory holds this device's key and is not reachable through the file browser")
	}
	return clean, nil
}

// fsCheckWritePath is fsCheckPath plus the rules that only matter when
// something is about to be created, overwritten or removed.
func fsCheckWritePath(p string) (string, error) {
	clean, err := fsCheckPath(p)
	if err != nil {
		return "", err
	}
	if fsIsRoot(clean) {
		return "", errors.New("refusing to modify a filesystem root")
	}
	return clean, nil
}

func fsList(p string) (*protocol.FsListResult, error) {
	if p == "" {
		return fsRoots()
	}
	clean, err := fsCheckPath(p)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(fsOSPath(clean))
	if err != nil {
		return nil, err
	}
	out := &protocol.FsListResult{Path: clean, Entries: []protocol.FsEntry{}}
	truncated := false
	if len(entries) > fsMaxEntries {
		entries, truncated = entries[:fsMaxEntries], true
	}
	for _, e := range entries {
		fe := protocol.FsEntry{Name: e.Name(), Path: filepath.Join(clean, e.Name()), IsDir: e.IsDir()}
		if info, err := e.Info(); err == nil {
			fe.Size = info.Size()
			fe.ModTime = info.ModTime().Unix()
			fe.Mode = info.Mode().String()
			// A Windows directory junction is a reparse point, not a symlink,
			// so ModeSymlink alone reported one as a file: the console drew it
			// with a file icon, would not open it, and offered a download that
			// could only fail. ModeIrregular covers the junction case.
			if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
				if st, err := os.Stat(fsOSPath(fe.Path)); err == nil && st.IsDir() {
					fe.IsDir = true
				}
			}
		}
		out.Entries = append(out.Entries, fe)
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		if out.Entries[i].IsDir != out.Entries[j].IsDir {
			return out.Entries[i].IsDir
		}
		return strings.ToLower(out.Entries[i].Name) < strings.ToLower(out.Entries[j].Name)
	})
	if truncated {
		out.Truncated = true
	}
	return out, nil
}

func fsRoots() (*protocol.FsListResult, error) {
	out := &protocol.FsListResult{Path: "", Entries: []protocol.FsEntry{}}
	if runtime.GOOS != "windows" {
		out.Entries = append(out.Entries, protocol.FsEntry{Name: "/", Path: "/", IsDir: true})
		if home, err := os.UserHomeDir(); err == nil && home != "/" {
			out.Entries = append(out.Entries, protocol.FsEntry{Name: "home (" + home + ")", Path: home, IsDir: true})
		}
		return out, nil
	}
	for c := 'A'; c <= 'Z'; c++ {
		d := string(c) + `:\`
		if _, err := os.Stat(d); err == nil {
			out.Entries = append(out.Entries, protocol.FsEntry{Name: d, Path: d, IsDir: true})
		}
	}
	return out, nil
}

func fsRead(req protocol.FsRead) (*protocol.FsReadResult, error) {
	clean, err := fsCheckPath(req.Path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(fsOSPath(clean))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, errors.New("is a directory")
	}
	length := req.Length
	if length <= 0 || length > fsMaxRead {
		length = fsMaxRead
	}
	if _, err := f.Seek(req.Offset, io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, length)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return &protocol.FsReadResult{Data: buf[:n], Size: st.Size(), EOF: req.Offset+int64(n) >= st.Size()}, nil
}

func fsWrite(req protocol.FsWrite) error {
	clean, err := fsCheckWritePath(req.Path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(fsOSPath(filepath.Dir(clean)), 0o755); err != nil {
		return err
	}
	flags := os.O_CREATE | os.O_WRONLY
	if req.Append {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(fsOSPath(clean), flags, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(req.Data)
	return err
}

func fsMkdir(p string) error {
	clean, err := fsCheckWritePath(p)
	if err != nil {
		return err
	}
	return os.MkdirAll(fsOSPath(clean), 0o755)
}

// fsRename refuses to land on an existing name. os.Rename replaces the
// destination silently on both platforms, so renaming report.txt onto
// config.txt in a live directory destroyed config.txt and answered ok.
func fsRename(from, to string) error {
	src, err := fsCheckWritePath(from)
	if err != nil {
		return err
	}
	dst, err := fsCheckWritePath(to)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(fsOSPath(src)); err != nil {
		return err
	}
	if _, err := os.Lstat(fsOSPath(dst)); err == nil {
		return fmt.Errorf("%s already exists", dst)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(fsOSPath(src), fsOSPath(dst))
}

// fsDelete reports what actually happened. It used to answer ok for a path
// that did not exist and for a Windows name RemoveAll could not address, so
// the console showed "Deleted X" and wrote an audit row for a file that was
// still there.
func fsDelete(p string) error {
	clean, err := fsCheckWritePath(p)
	if err != nil {
		return err
	}
	osPath := fsOSPath(clean)
	if _, err := os.Lstat(osPath); err != nil {
		return err
	}
	if err := os.RemoveAll(osPath); err != nil {
		return err
	}
	if _, err := os.Lstat(osPath); err == nil {
		return fmt.Errorf("%s is still present after the delete", clean)
	}
	return nil
}
