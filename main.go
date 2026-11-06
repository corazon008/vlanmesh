package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"vlanmesh/internal/config"
	"vlanmesh/internal/model"
	"vlanmesh/internal/monitor"
	"vlanmesh/internal/netcfg"
	"vlanmesh/internal/server"
	"vlanmesh/internal/store"
)

var version = "dev"

func main() {
	var (
		cfgPath = flag.String("config", envOr("VLANMESH_CONFIG", "config.yaml"), "path to config.yaml")
		once    = flag.Bool("once", false, "run a single sweep, print the matrix and exit")
		check   = flag.Bool("check", false, "validate config and network setup, then exit")
		showVer = flag.Bool("version", false, "print version and exit")
		verbose = flag.Bool("v", false, "debug logs")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if *showVer {
		fmt.Println("vlanmesh", version)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("config", err)
	}

	if *check {
		slog.Info("config OK", "vlans", len(cfg.VLANS), "targets", cfg.Targets.Mode, "demo", cfg.Demo)
		for _, v := range cfg.VLANS {
			fmt.Printf("  %-10s iface=%-6s src=%-20s gw=%-16s target=%s\n", v.Name, v.Iface, v.Src, v.Gateway, cfg.Targets.For(v))
		}
		issues := netcfg.Diagnose(cfg)
		if len(issues) == 0 {
			fmt.Println("network: OK")
			return
		}
		fmt.Println("network issues:")
		for _, i := range issues {
			fmt.Println("  -", i)
		}
		os.Exit(2)
	}

	var issues []string
	if !cfg.Demo {
		issues = netcfg.Apply(cfg)
		for _, i := range issues {
			slog.Warn("network", "issue", i)
		}
	}

	st, err := store.Open(cfg.DB)
	if err != nil {
		fatal("open database", err)
	}
	defer st.Close()

	mon := monitor.New(cfg, st, issues)
	mon.Prime()

	if *once {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		mon.Sweep(ctx)
		printMatrix(cfg, mon.Snapshot())
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go mon.Run(ctx)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.New(mon, st, version),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		slog.Info("vlanmesh started", "listen", cfg.Listen, "version", version, "demo", cfg.Demo, "vlans", len(cfg.VLANS))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal("http server", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func printMatrix(cfg *config.Config, snap model.Snapshot) {
	byKey := make(map[model.Key]model.Cell, len(snap.Cells))
	for _, c := range snap.Cells {
		byKey[model.Key{Src: c.Src, Dst: c.Dst}] = c
	}

	const w = 14
	fmt.Printf("%-12s", "src \\ dst")
	for _, v := range cfg.VLANS {
		fmt.Printf("%-*s", w, trunc(v.Name, w-1))
	}
	fmt.Println()
	for _, src := range cfg.VLANS {
		fmt.Printf("%-12s", trunc(src.Name, 11))
		for _, dst := range cfg.VLANS {
			c, ok := byKey[model.Key{Src: src.Name, Dst: dst.Name}]
			cell := "-"
			if ok {
				cell = matrixCell(c)
			}
			fmt.Printf("%-*s", w, trunc(cell, w-1))
		}
		fmt.Println()
	}
	fmt.Printf("sweep #%d  %s  %d cells  %d violation(s)\n",
		snap.Summary.Sweeps, snap.Summary.LastSweep, len(snap.Cells), snap.Summary.Violations)
	for _, i := range snap.Issues {
		fmt.Println("warning:", i)
	}
}

func matrixCell(c model.Cell) string {
	if c.Src == c.Dst {
		return "ctl " + statusShort(c.Status)
	}
	if c.RTTMin > 0 {
		return fmt.Sprintf("%s %.2fms", statusShort(c.Status), c.RTTAvg)
	}
	return statusShort(c.Status)
}

func statusShort(s model.Status) string {
	switch s {
	case model.StatusOK:
		return "OK"
	case model.StatusDegraded:
		return "DEGRADED"
	case model.StatusRejected:
		return "REJECT"
	case model.StatusUnreachable:
		return "UNREACH"
	case model.StatusTimeout:
		return "BLOCKED"
	case model.StatusUnknown:
		return "UNKNOWN"
	case model.StatusError:
		return "ERROR"
	}
	return strings.ToUpper(string(s))
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatal(msg string, err error) {
	fmt.Fprintf(os.Stderr, "vlanmesh: %s: %v\n", msg, err)
	os.Exit(1)
}
