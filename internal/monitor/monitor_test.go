package monitor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"vlanmesh/internal/config"
	"vlanmesh/internal/model"
	"vlanmesh/internal/store"
)

func testConfig() *config.Config {
	return &config.Config{
		Interval:    config.Duration(5 * time.Second),
		Timeout:     config.Duration(time.Second),
		Count:       2,
		Concurrency: 4,
		Demo:        true,
		VLANS: []config.VLAN{
			{Name: "vlan10", Iface: "eth1", Src: "192.168.10.5/24", Gateway: "192.168.10.254"},
			{Name: "vlan20", Iface: "eth2", Src: "192.168.20.5/24", Gateway: "192.168.20.254"},
			{Name: "vlan30", Iface: "eth3", Src: "192.168.30.5/24", Gateway: "192.168.30.254"},
		},
		Targets: config.Targets{Mode: "gateway", Hosts: map[string]string{}},
		Policy: config.Policy{
			Default: "allow",
			Rules:   []config.Rule{{From: "vlan10", To: "vlan20", Action: "deny"}},
		},
	}
}

func TestDemoSweep(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	m := New(testConfig(), st, nil)
	m.Sweep(context.Background())

	snap := m.Snapshot()
	if len(snap.Cells) != 9 {
		t.Fatalf("cells: got %d, want 9", len(snap.Cells))
	}
	if snap.Summary.Sweeps != 1 {
		t.Errorf("sweeps=%d", snap.Summary.Sweeps)
	}

	for _, c := range snap.Cells {
		if c.Src == c.Dst {
			if c.Status != model.StatusOK {
				t.Errorf("control %s: status=%s, want ok", c.Src, c.Status)
			}
			if c.Expected != "" || c.Violation != "" {
				t.Errorf("control %s: expected/violation should be empty", c.Src)
			}
			continue
		}
		switch {
		case c.Expected == "allow" && !c.Status.Reachable():
			if c.Violation != "unexpected_deny" {
				t.Errorf("%s->%s: allow+blocked must be unexpected_deny, got %q", c.Src, c.Dst, c.Violation)
			}
		case c.Expected == "deny" && c.Status.Reachable():
			if c.Violation != "unexpected_allow" {
				t.Errorf("%s->%s: deny+reachable must be unexpected_allow, got %q", c.Src, c.Dst, c.Violation)
			}
		default:
			if c.Violation != "" {
				t.Errorf("%s->%s: unexpected violation %q", c.Src, c.Dst, c.Violation)
			}
		}
	}

	// History is persisted and reloadable.
	hist, err := st.History("vlan10", "vlan20", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 {
		t.Fatalf("history: got %d, want 1", len(hist))
	}
}

func TestSnapshotBeforeSweep(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	m := New(testConfig(), st, []string{"test issue"})
	snap := m.Snapshot()
	if len(snap.Cells) != 0 {
		t.Errorf("cells: got %d, want 0", len(snap.Cells))
	}
	if len(snap.Vlans) != 3 {
		t.Errorf("vlans: got %d", len(snap.Vlans))
	}
	if len(snap.Issues) != 1 {
		t.Errorf("issues: got %d", len(snap.Issues))
	}
}
