package model

import "time"

type Status string

const (
	StatusOK          Status = "ok"
	StatusDegraded    Status = "degraded"
	StatusRejected    Status = "rejected"
	StatusUnreachable Status = "unreachable"
	StatusTimeout     Status = "timeout"
	StatusError       Status = "error"
	StatusUnknown     Status = "unknown"
)

func (s Status) Reachable() bool {
	return s == StatusOK || s == StatusDegraded
}

// Result is the outcome of one directed probe (src VLAN -> target).
type Result struct {
	Src      string    `json:"src"`
	Dst      string    `json:"dst"`
	SrcIP    string    `json:"src_ip"`
	DstIP    string    `json:"dst_ip"`
	Status   Status    `json:"status"`
	Sent     int       `json:"sent"`
	Recv     int       `json:"recv"`
	Loss     float64   `json:"loss"`
	RTTMin   float64   `json:"rtt_min_ms"`
	RTTAvg   float64   `json:"rtt_avg_ms"`
	RTTMax   float64   `json:"rtt_max_ms"`
	ICMPType int       `json:"icmp_type"`
	ICMPCode int       `json:"icmp_code"`
	Err      string    `json:"error,omitempty"`
	Started  time.Time `json:"started_at"`
	Duration float64   `json:"duration_ms"`
}

type Key struct {
	Src string
	Dst string
}

// Cell is a Result enriched with the expected policy and its verdict.
type Cell struct {
	Result
	Expected  string    `json:"expected,omitempty"`
	Violation string    `json:"violation,omitempty"` // unexpected_allow | unexpected_deny
	CheckedAt time.Time `json:"checked_at"`
}

type VLANInfo struct {
	Name    string `json:"name"`
	VLANID  int    `json:"vlan_id"`
	Iface   string `json:"iface"`
	Src     string `json:"src"`
	Gateway string `json:"gateway"`
	Target  string `json:"target"`
}

type PolicyInfo struct {
	Default string       `json:"default"`
	Rules   []PolicyRule `json:"rules"`
}

type PolicyRule struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Action string `json:"action"`
}

type Snapshot struct {
	GeneratedAt time.Time  `json:"generated_at"`
	Interval    string     `json:"interval"`
	Demo        bool       `json:"demo"`
	TargetsMode string     `json:"targets_mode"`
	Vlans       []VLANInfo `json:"vlans"`
	Policy      PolicyInfo `json:"policy"`
	Cells       []Cell     `json:"cells"`
	Summary     Summary    `json:"summary"`
	Issues      []string   `json:"issues,omitempty"`
}

type Summary struct {
	OK         int    `json:"ok"`
	Degraded   int    `json:"degraded"`
	Blocked    int    `json:"blocked"`
	Unknown    int    `json:"unknown"`
	Violations int    `json:"violations"`
	LastSweep  string `json:"last_sweep,omitempty"`
	Sweeps     uint64 `json:"sweeps"`
}
