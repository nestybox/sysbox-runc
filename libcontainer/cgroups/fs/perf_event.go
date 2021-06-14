// +build linux

package fs

import (
	"fmt"
	"os"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	"github.com/opencontainers/runc/libcontainer/configs"
)

type PerfEventGroup struct {
}

func (s *PerfEventGroup) Name() string {
	return "perf_event"
}

func (s *PerfEventGroup) Apply(path string, d *cgroupData) error {
	return join(path, d.pid)
}

func (s *PerfEventGroup) Set(path string, cgroup *configs.Cgroup) error {
	return nil
}

func (s *PerfEventGroup) GetStats(path string, stats *cgroups.Stats) error {
	return nil
}

func (s *PerfEventGroup) Clone(source, dest string) error {

	if err := fscommon.WriteFile(source, "cgroup.clone_children", "1"); err != nil {
		return err
	}

	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("Failed to create cgroup %s", dest)
	}

	return nil
}
