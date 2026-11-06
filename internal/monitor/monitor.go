package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"vlanmesh/internal/config"
	"vlanmesh/internal/metrics"
	"vlanmesh/internal/model"
	"vlanmesh/internal/probe"
	"vlanmesh/internal/store"
)

type Monitor struct {
	cfg    *config.Config
	st     *store.Store
	issues []string
	client *http.Client

	mu            sync.RWMutex
	cells         map[model.Key]model.Cell
	lastSweep     time.Time
	sweeps        uint64
	prevStatus    map[model.Key]model.Status
	prevViolation map[model.Key]string

	running atomic.Bool
}

func New(cfg *config.Config, st *store.Store, issues []string) *Monitor {
	return &Monitor{
		cfg:           cfg,
		st:            st,
		issues:        issues,
		client:        &http.Client{Timeout: 5 * time.Second},
		cells:         map[model.Key]model.Cell{},
		prevStatus:    map[model.Key]model.Status{},
		prevViolation: map[model.Key]string{},
	}
}

// Prime loads the last known state from the database so the UI is not empty
// after a restart.
func (m *Monitor) Prime() {
	cells, err := m.st.LatestAll()
	if err != nil {
		slog.Warn("load last state", "err", err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range cells {
		m.cells[model.Key{Src: c.Src, Dst: c.Dst}] = c
	}
	slog.Info("loaded previous state", "cells", len(cells))
}

func (m *Monitor) Run(ctx context.Context) {
	m.Sweep(ctx)
	ticker := time.NewTicker(m.cfg.Interval.D())
	defer ticker.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Sweep(ctx)
		case <-prune.C:
			if err := m.st.Prune(time.Now().Add(-m.cfg.Retention.D())); err != nil {
				slog.Warn("prune history", "err", err)
			}
		}
	}
}

type job struct {
	src     config.VLAN
	dst     config.VLAN
	dstIP   string
	control bool
}

func (m *Monitor) Sweep(ctx context.Context) {
	if !m.running.CompareAndSwap(false, true) {
		slog.Warn("sweep still running, skipping tick")
		return
	}
	defer m.running.Store(false)
	if ctx.Err() != nil {
		return
	}

	started := time.Now()
	jobs := m.buildJobs()

	results := make([]model.Result, len(jobs))
	sem := make(chan struct{}, m.cfg.Concurrency)
	var wg sync.WaitGroup
	for idx := range jobs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			j := jobs[idx]
			var r model.Result
			if m.cfg.Demo {
				r = m.demoResult(j)
			} else {
				r = probe.Probe(j.src.SrcIP(), j.src.Iface, j.dstIP, m.cfg.Count, m.cfg.Timeout.D())
			}
			r.Src = j.src.Name
			r.Dst = j.dst.Name
			if r.SrcIP == "" {
				r.SrcIP = j.src.SrcIP()
			}
			if r.DstIP == "" {
				r.DstIP = j.dstIP
			}
			results[idx] = r
		}(idx)
	}
	wg.Wait()

	now := time.Now()
	controls := make(map[string]bool, len(m.cfg.VLANS))
	for i, j := range jobs {
		if j.control {
			controls[j.src.Name] = results[i].Status.Reachable()
		}
	}

	cells := make([]model.Cell, len(jobs))
	for i, j := range jobs {
		c := model.Cell{Result: results[i], CheckedAt: now}
		if !j.control {
			exp, _ := m.cfg.Policy.Expected(j.src.Name, j.dst.Name)
			c.Expected = exp

			if !controls[j.src.Name] {
				c.Status = model.StatusUnknown
				if c.Err == "" {
					c.Err = "control probe to own gateway failed"
				}
				c.Loss = 1
			} else if exp != "" {
				reach := c.Status.Reachable()
				switch {
				case exp == "allow" && !reach:
					c.Violation = "unexpected_deny"
				case exp == "deny" && reach:
					c.Violation = "unexpected_allow"
				}
			}
		}
		cells[i] = c
	}

	if err := m.st.Insert(cells); err != nil {
		slog.Error("persist sweep", "err", err)
	}

	changes := m.commit(cells, now)
	m.updateMetrics(cells, now.Sub(started))
	m.notify(changes, now)

	slog.Info("sweep done", "cells", len(cells), "duration", time.Since(started).Round(time.Millisecond))
}

func (m *Monitor) buildJobs() []job {
	vlans := m.cfg.VLANS
	jobs := make([]job, 0, len(vlans)*len(vlans))
	for i := range vlans {
		for j := range vlans {
			src := vlans[i]
			dst := vlans[j]
			jb := job{src: src, dst: dst, control: i == j}
			if i == j {
				// Control probe: own gateway, on-link, never crosses the firewall.
				jb.dstIP = src.Gateway
			} else {
				jb.dstIP = m.cfg.Targets.For(dst)
			}
			jobs = append(jobs, jb)
		}
	}
	return jobs
}

// commit swaps the in-memory state and returns the cells whose status changed.
func (m *Monitor) commit(cells []model.Cell, at time.Time) []model.Cell {
	m.mu.Lock()
	defer m.mu.Unlock()

	next := make(map[model.Key]model.Cell, len(cells))
	var changes []model.Cell
	for _, c := range cells {
		k := model.Key{Src: c.Src, Dst: c.Dst}
		next[k] = c
		if old, ok := m.cells[k]; ok && old.Status != c.Status {
			changes = append(changes, c)
		}
	}
	m.cells = next
	m.lastSweep = at
	m.sweeps++
	return changes
}

func (m *Monitor) updateMetrics(cells []model.Cell, dur time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, c := range cells {
		k := model.Key{Src: c.Src, Dst: c.Dst}
		reachable := c.Status.Reachable()
		v := 0.0
		if reachable {
			v = 1
		}
		metrics.ProbeSuccess.WithLabelValues(c.Src, c.Dst).Set(v)
		metrics.ProbeLoss.WithLabelValues(c.Src, c.Dst).Set(c.Loss)
		metrics.ProbeRTT.WithLabelValues(c.Src, c.Dst, "min").Set(c.RTTMin)
		metrics.ProbeRTT.WithLabelValues(c.Src, c.Dst, "avg").Set(c.RTTAvg)
		metrics.ProbeRTT.WithLabelValues(c.Src, c.Dst, "max").Set(c.RTTMax)

		if old, ok := m.prevStatus[k]; ok && old != c.Status {
			metrics.ProbeStatus.DeleteLabelValues(c.Src, c.Dst, string(old))
		}
		metrics.ProbeStatus.WithLabelValues(c.Src, c.Dst, string(c.Status)).Set(1)
		m.prevStatus[k] = c.Status

		if old, ok := m.prevViolation[k]; ok && old != c.Violation {
			metrics.PolicyViolation.DeleteLabelValues(c.Src, c.Dst, old)
			delete(m.prevViolation, k)
		}
		if c.Violation != "" {
			metrics.PolicyViolation.WithLabelValues(c.Src, c.Dst, c.Violation).Set(1)
			m.prevViolation[k] = c.Violation
		}
	}

	metrics.LastSweep.SetToCurrentTime()
	metrics.SweepDuration.Set(dur.Seconds())
	metrics.SweepsTotal.Inc()
	metrics.CellsTotal.Set(float64(len(cells)))
}

type alertPayload struct {
	Type    string       `json:"type"`
	At      time.Time    `json:"at"`
	Message string       `json:"message"`
	Cells   []model.Cell `json:"cells"`
}

func (m *Monitor) notify(changes []model.Cell, at time.Time) {
	if m.cfg.Alerts.Webhook == "" || len(changes) == 0 {
		return
	}
	payload := alertPayload{
		Type:    "state_change",
		At:      at,
		Message: "vlanmesh: connectivity state changed",
		Cells:   changes,
	}
	go func() {
		b, err := json.Marshal(payload)
		if err != nil {
			return
		}
		req, err := http.NewRequest(http.MethodPost, m.cfg.Alerts.Webhook, bytes.NewReader(b))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "vlanmesh")
		resp, err := m.client.Do(req)
		if err != nil {
			slog.Warn("webhook failed", "err", err)
			return
		}
		resp.Body.Close()
	}()
}

func (m *Monitor) Snapshot() model.Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	order := make(map[string]int, len(m.cfg.VLANS))
	for i, v := range m.cfg.VLANS {
		order[v.Name] = i
	}

	cells := make([]model.Cell, 0, len(m.cells))
	for _, c := range m.cells {
		cells = append(cells, c)
	}
	sort.Slice(cells, func(i, j int) bool {
		oi, oj := order[cells[i].Src], order[cells[j].Src]
		if oi != oj {
			return oi < oj
		}
		return order[cells[i].Dst] < order[cells[j].Dst]
	})

	sum := model.Summary{Sweeps: m.sweeps}
	for _, c := range cells {
		switch c.Status {
		case model.StatusOK:
			sum.OK++
		case model.StatusDegraded:
			sum.Degraded++
		case model.StatusRejected, model.StatusUnreachable, model.StatusTimeout:
			sum.Blocked++
		default:
			sum.Unknown++
		}
		if c.Violation != "" {
			sum.Violations++
		}
	}
	if !m.lastSweep.IsZero() {
		sum.LastSweep = m.lastSweep.UTC().Format(time.RFC3339)
	}

	vlans := make([]model.VLANInfo, 0, len(m.cfg.VLANS))
	for _, v := range m.cfg.VLANS {
		vlans = append(vlans, model.VLANInfo{
			Name:    v.Name,
			VLANID:  v.VLANID,
			Iface:   v.Iface,
			Src:     v.Src,
			Gateway: v.Gateway,
			Target:  m.cfg.Targets.For(v),
		})
	}

	pol := model.PolicyInfo{Default: m.cfg.Policy.Default}
	for _, r := range m.cfg.Policy.Rules {
		pol.Rules = append(pol.Rules, model.PolicyRule{From: r.From, To: r.To, Action: r.Action})
	}

	return model.Snapshot{
		GeneratedAt: time.Now().UTC(),
		Interval:    m.cfg.Interval.D().String(),
		Demo:        m.cfg.Demo,
		TargetsMode: m.cfg.Targets.Mode,
		Vlans:       vlans,
		Policy:      pol,
		Cells:       cells,
		Summary:     sum,
		Issues:      m.issues,
	}
}

// demoResult keeps the dashboard fully functional on a machine without the
// VLAN interfaces. It follows the declared policy, with a little noise.
func (m *Monitor) demoResult(j job) model.Result {
	r := model.Result{
		Started: time.Now(),
		SrcIP:   j.src.SrcIP(),
		DstIP:   j.dstIP,
		Sent:    m.cfg.Count,
	}
	roll := rand.Float64()
	lat := 0.25 + rand.Float64()*1.8

	if j.control {
		r.Status = model.StatusOK
		r.Recv = r.Sent
		r.RTTMin, r.RTTMax, r.RTTAvg = lat, lat+0.2, lat+0.1
		r.Duration = r.RTTAvg
		return r
	}

	exp, _ := m.cfg.Policy.Expected(j.src.Name, j.dst.Name)
	allowed := exp != "deny"

	if allowed {
		switch {
		case roll < 0.90:
			r.Status = model.StatusOK
			r.Recv = r.Sent
		case roll < 0.96:
			r.Status = model.StatusDegraded
			r.Recv = r.Sent - 1
			r.Err = "partial loss"
		default:
			r.Status = model.StatusTimeout
			r.Recv = 0
			r.Err = "no reply (simulated)"
		}
	} else {
		switch {
		case roll < 0.90:
			r.Status = model.StatusTimeout
			r.Recv = 0
			r.Err = "no reply (simulated)"
		case roll < 0.98:
			r.Status = model.StatusRejected
			r.Recv = 0
			r.ICMPType, r.ICMPCode = 3, 13
			r.Err = "icmp unreachable (type 3 code 13)"
		default:
			r.Status = model.StatusOK
			r.Recv = r.Sent
		}
	}

	if r.Recv > 0 {
		r.Loss = 1 - float64(r.Recv)/float64(r.Sent)
		r.RTTMin = lat
		r.RTTMax = lat + rand.Float64()*1.5
		r.RTTAvg = (r.RTTMin + r.RTTMax) / 2
	} else {
		r.Loss = 1
	}
	r.Duration = r.RTTAvg
	return r
}
