package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Uploads in two steps. In an organisation that signs actions an operator
// cannot sign a file's bytes (they would have to travel inside the manifest),
// so the server streams them with fs.stage into a staging area inside this
// agent's own configuration directory - which the file browser refuses to
// reach (fsCheckPath) and so nothing can read or run - and the operator signs
// fs.commit: a destination, a size and a SHA-256. The commit copies the
// staged bytes next to the destination while hashing them and renames the
// copy into place only when they match, so the bytes that land are exactly
// the bytes that were checked, whatever the server stages before or during
// the commit.

const (
	stagingDirName  = "staging"
	maxStagedUpload = 16 << 30  // a hostile server must not be able to fill the disk through staging
	stagedUploadTTL = time.Hour // abandoned uploads are removed after this
)

var uploadIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// stageMu serialises staging and commits: a chunk can never be appended to a
// file while it is being committed. Uploads are rare; one lock is enough.
var stageMu sync.Mutex

func stagingDir() string { return filepath.Join(ConfigDir(), stagingDirName) }

// stagingPath maps an upload ID to its staging file. The ID comes from the
// server, so it is checked against a strict pattern before it touches a path.
func stagingPath(id string) (string, error) {
	if !uploadIDRE.MatchString(id) {
		return "", errors.New("invalid upload id")
	}
	return filepath.Join(stagingDir(), id+".part"), nil
}

func fsStage(req protocol.FsStage) error {
	p, err := stagingPath(req.UploadID)
	if err != nil {
		return err
	}
	if req.Offset < 0 || req.Offset+int64(len(req.Data)) > maxStagedUpload {
		return fmt.Errorf("upload %s: staging is limited to %d GiB", req.UploadID, maxStagedUpload>>30)
	}
	stageMu.Lock()
	defer stageMu.Unlock()
	if err := os.MkdirAll(stagingDir(), 0o700); err != nil {
		return err
	}
	flags := os.O_CREATE | os.O_WRONLY
	if req.Offset == 0 {
		pruneStaging(time.Now())
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(p, flags, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() != req.Offset {
		return fmt.Errorf("upload %s: chunk at offset %d, but %d bytes are staged", req.UploadID, req.Offset, st.Size())
	}
	if _, err := f.Seek(req.Offset, io.SeekStart); err != nil {
		return err
	}
	_, err = f.Write(req.Data)
	return err
}

// pruneStaging removes staging files nobody committed within the TTL.
// Caller holds stageMu.
func pruneStaging(now time.Time) {
	entries, err := os.ReadDir(stagingDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".part") {
			continue
		}
		if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > stagedUploadTTL {
			os.Remove(filepath.Join(stagingDir(), e.Name()))
		}
	}
}

func fsCommit(req protocol.FsCommit) error {
	src, err := stagingPath(req.UploadID)
	if err != nil {
		return err
	}
	dest, err := fsCheckWritePath(req.Path)
	if err != nil {
		return err
	}
	want := strings.ToLower(req.SHA256)
	if b, err := hex.DecodeString(want); err != nil || len(b) != sha256.Size {
		return errors.New("commit needs a SHA-256 in hex")
	}
	if req.Size < 0 || req.Size > maxStagedUpload {
		return errors.New("commit size is out of range")
	}

	stageMu.Lock()
	defer stageMu.Unlock()
	in, err := os.Open(src)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("upload %s is not staged on this device (it may have expired)", req.UploadID)
	}
	if err != nil {
		return err
	}
	destOS := fsOSPath(dest)
	if err := os.MkdirAll(filepath.Dir(destOS), 0o755); err != nil {
		in.Close()
		return err
	}
	// The copy lands beside the destination so the final rename stays on one
	// volume; the staging area may be on another.
	tmp, err := os.CreateTemp(filepath.Dir(destOS), ".rmm-upload-*")
	if err != nil {
		in.Close()
		return err
	}
	discard := func(e error) error {
		tmp.Close()
		os.Remove(tmp.Name())
		return e
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(in, req.Size+1))
	in.Close()
	if err != nil {
		return discard(err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); n != req.Size || got != want {
		// Useless now: whatever was staged is not what the operator signed.
		os.Remove(src)
		return discard(fmt.Errorf("staged upload does not match what was signed (%d bytes, sha256 %s; signed %d bytes, sha256 %s)", n, got, req.Size, want))
	}
	if err := tmp.Sync(); err != nil {
		return discard(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	os.Chmod(tmp.Name(), 0o644) // what fsWrite creates; ignored on Windows
	if err := os.Rename(tmp.Name(), destOS); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	os.Remove(src)
	return nil
}
