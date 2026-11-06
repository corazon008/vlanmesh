package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"vlanmesh/internal/metrics"
	"vlanmesh/internal/model"
	"vlanmesh/internal/monitor"
	"vlanmesh/internal/store"
	"vlanmesh/internal/web"
)

type Server struct {
	mon     *monitor.Monitor
	st      *store.Store
	version string
}

func New(mon *monitor.Monitor, st *store.Store, version string) http.Handler {
	s := &Server{mon: mon, st: st, version: version}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /api/matrix", s.matrix)
	mux.HandleFunc("GET /api/history", s.history)
	mux.HandleFunc("GET /api/health", s.health)
	mux.Handle("GET /metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}))

	return logging(mux)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(web.IndexHTML)
}

func (s *Server) matrix(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mon.Snapshot())
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("src")
	dst := r.URL.Query().Get("dst")
	if src == "" || dst == "" {
		http.Error(w, "src and dst are required", http.StatusBadRequest)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	cells, err := s.st.History(src, dst, limit)
	if err != nil {
		slog.Error("history query", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if cells == nil {
		cells = []model.Cell{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"src":     src,
		"dst":     dst,
		"results": cells,
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	snap := s.mon.Snapshot()
	code := http.StatusOK
	if snap.Summary.OK+snap.Summary.Degraded+snap.Summary.Blocked+snap.Summary.Unknown == 0 {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{
		"status":     http.StatusText(code),
		"version":    s.version,
		"last_sweep": snap.Summary.LastSweep,
		"violations": snap.Summary.Violations,
		"demo":       snap.Demo,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		slog.Error("encode response", "err", err)
	}
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if r.URL.Path != "/api/matrix" && r.URL.Path != "/" {
			slog.Debug("http", "method", r.Method, "path", r.URL.Path, "dur", time.Since(start).Round(time.Millisecond))
		}
	})
}
