package metrics

import "github.com/prometheus/client_golang/prometheus"

// Registry is a dedicated registry so we don't leak Go runtime metrics by
// default (they are still exposed under /metrics via the default collector if
// wanted).
var Registry = prometheus.NewRegistry()

var (
	ProbeSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vlanmesh_probe_success",
		Help: "1 if the directed probe is reachable (ok or degraded), else 0.",
	}, []string{"src", "dst"})

	InternetSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vlanmesh_internet_success",
		Help: "1 if the VLAN can reach the Internet targets, else 0.",
	}, []string{"src"})

	ProbeLoss = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vlanmesh_probe_loss_ratio",
		Help: "ICMP loss ratio of the last probe (0..1).",
	}, []string{"src", "dst"})

	ProbeRTT = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vlanmesh_probe_rtt_ms",
		Help: "ICMP round-trip time in milliseconds (stat=min|avg|max).",
	}, []string{"src", "dst", "stat"})

	ProbeStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vlanmesh_probe_status",
		Help: "Current status of a directed probe, 1 for the active status label.",
	}, []string{"src", "dst", "status"})

	PolicyViolation = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vlanmesh_policy_violation",
		Help: "1 when the observed result contradicts the expected policy.",
	}, []string{"src", "dst", "type"})

	LastSweep = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vlanmesh_last_sweep_timestamp_seconds",
		Help: "Unix timestamp of the last completed sweep.",
	})

	SweepDuration = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vlanmesh_sweep_duration_seconds",
		Help: "Duration of the last sweep.",
	})

	SweepsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vlanmesh_sweeps_total",
		Help: "Total number of completed sweeps.",
	})

	CellsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vlanmesh_cells_total",
		Help: "Number of directed cells in the matrix.",
	})
)

func init() {
	Registry.MustRegister(ProbeSuccess, InternetSuccess, ProbeLoss, ProbeRTT, ProbeStatus, PolicyViolation,
		LastSweep, SweepDuration, SweepsTotal, CellsTotal)
}
