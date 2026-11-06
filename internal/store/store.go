package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"vlanmesh/internal/model"
)

type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS probes (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         INTEGER NOT NULL,
	src        TEXT    NOT NULL,
	dst        TEXT    NOT NULL,
	src_ip     TEXT    NOT NULL,
	dst_ip     TEXT    NOT NULL,
	status     TEXT    NOT NULL,
	sent       INTEGER NOT NULL,
	recv       INTEGER NOT NULL,
	loss       REAL    NOT NULL,
	rtt_min    REAL    NOT NULL,
	rtt_avg    REAL    NOT NULL,
	rtt_max    REAL    NOT NULL,
	icmp_type  INTEGER NOT NULL,
	icmp_code  INTEGER NOT NULL,
	err        TEXT    NOT NULL,
	expected   TEXT    NOT NULL,
	violation  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_probes_pair_ts ON probes(src, dst, ts DESC);
CREATE INDEX IF NOT EXISTS idx_probes_ts ON probes(ts);
`

func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Insert(cells []model.Cell) error {
	if len(cells) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO probes
		(ts, src, dst, src_ip, dst_ip, status, sent, recv, loss,
		 rtt_min, rtt_avg, rtt_max, icmp_type, icmp_code, err, expected, violation)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, c := range cells {
		ts := c.CheckedAt
		if ts.IsZero() {
			ts = time.Now()
		}
		if _, err := stmt.Exec(
			ts.UnixMilli(), c.Src, c.Dst, c.SrcIP, c.DstIP, string(c.Status),
			c.Sent, c.Recv, c.Loss, c.RTTMin, c.RTTAvg, c.RTTMax,
			c.ICMPType, c.ICMPCode, c.Err, c.Expected, c.Violation,
		); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

const columns = `ts, src, dst, src_ip, dst_ip, status, sent, recv, loss,
	rtt_min, rtt_avg, rtt_max, icmp_type, icmp_code, err, expected, violation`

func (s *Store) LatestAll() ([]model.Cell, error) {
	q := `SELECT ` + columns + ` FROM probes p
		WHERE ts = (SELECT MAX(ts) FROM probes q WHERE q.src = p.src AND q.dst = p.dst)`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Cell
	for rows.Next() {
		c, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) History(src, dst string, limit int) ([]model.Cell, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	q := `SELECT ` + columns + ` FROM probes WHERE src = ? AND dst = ? ORDER BY ts DESC LIMIT ?`
	rows, err := s.db.Query(q, src, dst, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Cell
	for rows.Next() {
		c, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Prune(before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM probes WHERE ts < ?`, before.UnixMilli())
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scan(r rowScanner) (model.Cell, error) {
	var (
		c         model.Cell
		ts        int64
		status    string
		icmpType  int
		icmpCode  int
		errText   string
		expected  string
		violation string
	)
	err := r.Scan(
		&ts, &c.Src, &c.Dst, &c.SrcIP, &c.DstIP, &status,
		&c.Sent, &c.Recv, &c.Loss, &c.RTTMin, &c.RTTAvg, &c.RTTMax,
		&icmpType, &icmpCode, &errText, &expected, &violation,
	)
	if err != nil {
		return c, err
	}
	c.Status = model.Status(status)
	c.ICMPType = icmpType
	c.ICMPCode = icmpCode
	c.Err = errText
	c.Expected = expected
	c.Violation = violation
	c.CheckedAt = time.UnixMilli(ts)
	return c, nil
}
