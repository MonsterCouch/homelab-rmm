package translog

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/tlog"
)

// Storage is append-only. AppendLeaf stores the leaf and the hashes
// tlog.StoredHashes returned for it in one transaction; indexes are dense
// from 0.
type Storage interface {
	Size() (int64, error)
	AppendLeaf(kind string, data []byte, hashes []tlog.Hash) (index int64, err error)
	// ReadHashes implements tlog.HashReader.
	ReadHashes(indexes []int64) ([]tlog.Hash, error)
	ReadLeaf(index int64) (kind string, data []byte, ts int64, err error)
}

// Schema is the DDL for SQLStorage. The server's migration runs it.
const Schema = `
CREATE TABLE IF NOT EXISTS tlog_leaves (
	idx  INTEGER PRIMARY KEY,
	kind TEXT NOT NULL,
	data BLOB NOT NULL,
	ts   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tlog_hashes (
	idx  INTEGER PRIMARY KEY,
	hash BLOB NOT NULL
);`

// SQLStorage keeps the log in a SQL database (tables from Schema).
type SQLStorage struct {
	db *sql.DB
}

// NewSQLStorage wraps db. The tables must already exist (run Schema).
func NewSQLStorage(db *sql.DB) *SQLStorage { return &SQLStorage{db: db} }

func (s *SQLStorage) Size() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM tlog_leaves`).Scan(&n)
	return n, err
}

func (s *SQLStorage) AppendLeaf(kind string, data []byte, hashes []tlog.Hash) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var index, base int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM tlog_leaves`).Scan(&index); err != nil {
		return 0, err
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM tlog_hashes`).Scan(&base); err != nil {
		return 0, err
	}
	if want := tlog.StoredHashCount(index); base != want {
		return 0, fmt.Errorf("the transparency log holds %d hashes for %d entries, expected %d; the log tables are damaged", base, index, want)
	}
	if _, err := tx.Exec(`INSERT INTO tlog_leaves(idx, kind, data, ts) VALUES(?,?,?,?)`,
		index, kind, data, time.Now().Unix()); err != nil {
		return 0, err
	}
	for i, h := range hashes {
		if _, err := tx.Exec(`INSERT INTO tlog_hashes(idx, hash) VALUES(?,?)`, base+int64(i), h[:]); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return index, nil
}

func (s *SQLStorage) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	// One query per chunk; a proof needs O(log n) hashes so there is
	// normally exactly one. The chunking only keeps us under SQLite's
	// bound-variable limit for callers that ask for more.
	const chunk = 500
	for start := 0; start < len(indexes); start += chunk {
		end := min(start+chunk, len(indexes))
		part := indexes[start:end]
		args := make([]any, len(part))
		pos := make(map[int64][]int, len(part))
		for i, ix := range part {
			args[i] = ix
			pos[ix] = append(pos[ix], start+i)
		}
		rows, err := s.db.Query(`SELECT idx, hash FROM tlog_hashes WHERE idx IN (`+
			strings.TrimSuffix(strings.Repeat("?,", len(part)), ",")+`)`, args...)
		if err != nil {
			return nil, err
		}
		found := 0
		for rows.Next() {
			var ix int64
			var b []byte
			if err := rows.Scan(&ix, &b); err != nil {
				rows.Close()
				return nil, err
			}
			if len(b) != tlog.HashSize {
				rows.Close()
				return nil, fmt.Errorf("the transparency log hash %d is %d bytes, expected %d", ix, len(b), tlog.HashSize)
			}
			for _, p := range pos[ix] {
				copy(out[p][:], b)
				found++
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if found != len(part) {
			return nil, errors.New("the transparency log is missing stored hashes it needs")
		}
	}
	return out, nil
}

func (s *SQLStorage) ReadLeaf(index int64) (string, []byte, int64, error) {
	var kind string
	var data []byte
	var ts int64
	err := s.db.QueryRow(`SELECT kind, data, ts FROM tlog_leaves WHERE idx=?`, index).Scan(&kind, &data, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, 0, fmt.Errorf("the transparency log has no entry %d", index)
	}
	return kind, data, ts, err
}

// MemStorage is an in-memory Storage for tests.
type MemStorage struct {
	mu     sync.Mutex
	kinds  []string
	data   [][]byte
	ts     []int64
	hashes []tlog.Hash
}

func NewMemStorage() *MemStorage { return &MemStorage{} }

func (m *MemStorage) Size() (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.data)), nil
}

func (m *MemStorage) AppendLeaf(kind string, data []byte, hashes []tlog.Hash) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if want := tlog.StoredHashCount(int64(len(m.data))); int64(len(m.hashes)) != want {
		return 0, errors.New("the transparency log hashes do not match its entries")
	}
	m.kinds = append(m.kinds, kind)
	m.data = append(m.data, append([]byte(nil), data...))
	m.ts = append(m.ts, time.Now().Unix())
	m.hashes = append(m.hashes, hashes...)
	return int64(len(m.data) - 1), nil
}

func (m *MemStorage) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]tlog.Hash, len(indexes))
	for i, ix := range indexes {
		if ix < 0 || ix >= int64(len(m.hashes)) {
			return nil, errors.New("the transparency log is missing stored hashes it needs")
		}
		out[i] = m.hashes[ix]
	}
	return out, nil
}

func (m *MemStorage) ReadLeaf(index int64) (string, []byte, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if index < 0 || index >= int64(len(m.data)) {
		return "", nil, 0, fmt.Errorf("the transparency log has no entry %d", index)
	}
	return m.kinds[index], append([]byte(nil), m.data[index]...), m.ts[index], nil
}
