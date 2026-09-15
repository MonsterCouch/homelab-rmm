package agent

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const fsMaxRead = 8 << 20

func fsList(p string) (*protocol.FsListResult, error) {
	if p == "" {
		return fsRoots()
	}
	p = filepath.Clean(p)
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	out := &protocol.FsListResult{Path: p, Entries: []protocol.FsEntry{}}
	for _, e := range entries {
		fe := protocol.FsEntry{Name: e.Name(), Path: filepath.Join(p, e.Name()), IsDir: e.IsDir()}
		if info, err := e.Info(); err == nil {
			fe.Size = info.Size()
			fe.ModTime = info.ModTime().Unix()
			fe.Mode = info.Mode().String()
			if info.Mode()&os.ModeSymlink != 0 {
				if st, err := os.Stat(fe.Path); err == nil && st.IsDir() {
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
	f, err := os.Open(req.Path)
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
	if err := os.MkdirAll(filepath.Dir(req.Path), 0o755); err != nil {
		return err
	}
	flags := os.O_CREATE | os.O_WRONLY
	if req.Append {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(req.Path, flags, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(req.Data)
	return err
}

func fsDelete(p string) error {
	p = filepath.Clean(p)
	if p == "/" || p == filepath.VolumeName(p)+`\` || p == "." {
		return errors.New("refusing to delete a root")
	}
	return os.RemoveAll(p)
}
