package fs

import (
	"fmt"
	"os"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	"github.com/opencontainers/runc/libcontainer/configs"
)

type RdmaGroup struct{}

func (s *RdmaGroup) Name() string {
	return "rdma"
}

func (s *RdmaGroup) Apply(path string, d *cgroupData) error {
	return join(path, d.pid)
}

func (s *RdmaGroup) Set(path string, r *configs.Resources) error {
	return fscommon.RdmaSet(path, r)
}

func (s *RdmaGroup) GetStats(path string, stats *cgroups.Stats) error {
	return fscommon.RdmaGetStats(path, stats)
}

func (s *RdmaGroup) Clone(source, dest string) error {

	if err := fscommon.WriteFile(source, "cgroup.clone_children", "1"); err != nil {
		return err
	}

	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("Failed to create cgroup %s", dest)
	}

	return nil
}
