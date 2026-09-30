package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
)

const (
	tagStartMarker = "[HOMELAB_RMM_CONFIG]"
	tagEndMarker   = "[END_HOMELAB_RMM_CONFIG]"
)

type taggedConfig struct {
	Server      string
	Token       string
	Fingerprint string
}

func readTaggedConfig(filePath string) (*taggedConfig, error) {
	if filePath == "" {
		return nil, errors.New("empty file path")
	}
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// Read up to last 64KB
	readSize := int64(64 * 1024)
	if st.Size() < readSize {
		readSize = st.Size()
	}
	buf := make([]byte, readSize)
	if _, err := f.ReadAt(buf, st.Size()-readSize); err != nil && err != io.EOF {
		return nil, err
	}

	startIdx := bytes.Index(buf, []byte(tagStartMarker))
	if startIdx == -1 {
		return nil, errors.New("tagged config marker not found")
	}
	endIdx := bytes.Index(buf[startIdx:], []byte(tagEndMarker))
	if endIdx == -1 {
		return nil, errors.New("end of tagged config marker not found")
	}
	content := string(buf[startIdx+len(tagStartMarker) : startIdx+endIdx])

	cfg := &taggedConfig{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SERVER=") {
			cfg.Server = strings.TrimPrefix(line, "SERVER=")
		} else if strings.HasPrefix(line, "TOKEN=") {
			cfg.Token = strings.TrimPrefix(line, "TOKEN=")
		} else if strings.HasPrefix(line, "FINGERPRINT=") {
			cfg.Fingerprint = strings.TrimPrefix(line, "FINGERPRINT=")
		}
	}
	if cfg.Server == "" || cfg.Token == "" {
		return nil, errors.New("tagged config missing required SERVER or TOKEN")
	}
	return cfg, nil
}
