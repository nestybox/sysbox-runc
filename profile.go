package main

import (
	"fmt"
	"runtime"

	"github.com/pkg/profile"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

// Run cpu / memory profiling collection.
func runProfiler(ctx *cli.Context) (interface{ Stop() }, error) {

	var prof interface{ Stop() }

	cpuProfOn := ctx.GlobalBool("cpu-profiling")
	memProfOn := ctx.GlobalBool("memory-profiling")

	// Typical (i.e., non-profiling) case.
	if !cpuProfOn && !memProfOn {
		return nil, nil
	}

	// Cpu and Memory profiling options seem to be mutually exclused in pprof.
	if cpuProfOn && memProfOn {
		return nil, fmt.Errorf("Unsupported parameter combination: cpu and memory profiling")
	}

	if cpuProfOn {

		// set the profiler's sampling rate at twice the usual to get a
		// more accurate result (sysbox-runc executes quickly).
		//
		// Note: this may result in the following error message when
		// running sysbox-runc with profiling enabled: "runtime: cannot
		// set cpu profile rate until previous profile has finished."
		// We can ignore it; it occurs because profile.Start() invokes
		// pprof.go which calls SetCPUProfileRate() again. Since we have
		// already set the value, the one from pprof will be ignored.
		runtime.SetCPUProfileRate(200)

		prof = profile.Start(
			profile.Quiet,
			profile.CPUProfile,
			profile.ProfilePath("."),
		)
		logrus.Info("Initiated cpu-profiling data collection.")
	}

	if memProfOn {
		prof = profile.Start(
			profile.Quiet,
			profile.MemProfile,
			profile.ProfilePath("."),
		)
		logrus.Info("Initiated memory-profiling data collection.")
	}

	return prof, nil
}
