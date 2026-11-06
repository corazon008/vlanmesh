package store

import (
	"path/filepath"
	"testing"
	"time"

	"vlanmesh/internal/model"
)

func TestInsertLatestHistory(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now()
	cells := []model.Cell{
		{Result: model.Result{Src: "vlan10", Dst: "vlan20", SrcIP: "192.168.10.5", DstIP: "192.168.20.254",
			Status: model.StatusOK, Sent: 3, Recv: 3, RTTAvg: 0.5}, CheckedAt: now.Add(-time.Minute), Expected: "allow"},
		{Result: model.Result{Src: "vlan10", Dst: "vlan20", SrcIP: "192.168.10.5", DstIP: "192.168.20.254",
			Status: model.StatusTimeout, Sent: 3, Recv: 0, Loss: 1}, CheckedAt: now, Expected: "allow", Violation: "unexpected_deny"},
		{Result: model.Result{Src: "vlan10", Dst: "vlan10", SrcIP: "192.168.10.5", DstIP: "192.168.10.254",
			Status: model.StatusOK, Sent: 3, Recv: 3}, CheckedAt: now},
	}
	if err := st.Insert(cells); err != nil {
		t.Fatal(err)
	}

	latest, err := st.LatestAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 2 {
		t.Fatalf("latest: got %d cells, want 2", len(latest))
	}
	for _, c := range latest {
		if c.Src == "vlan10" && c.Dst == "vlan20" {
			if c.Status != model.StatusTimeout {
				t.Errorf("latest status=%s, want timeout", c.Status)
			}
			if c.Violation != "unexpected_deny" {
				t.Errorf("latest violation=%q", c.Violation)
			}
		}
	}

	hist, err := st.History("vlan10", "vlan20", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("history: got %d, want 2", len(hist))
	}
	if hist[0].Status != model.StatusTimeout {
		t.Errorf("history must be newest first, got %s", hist[0].Status)
	}

	if err := st.Prune(now.Add(-30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	hist, err = st.History("vlan10", "vlan20", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 {
		t.Fatalf("after prune: got %d, want 1", len(hist))
	}
}
