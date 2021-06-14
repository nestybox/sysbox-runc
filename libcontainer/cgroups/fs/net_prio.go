// +build linux

package fs

import (
	"fmt"
	"os"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	"github.com/opencontainers/runc/libcontainer/configs"
)

type NetPrioGroup struct {
}

func (s *NetPrioGroup) Name() string {
	return "net_prio"
}

func (s *NetPrioGroup) Apply(path string, d *cgroupData) error {
	return join(path, d.pid)
}

func (s *NetPrioGroup) Set(path string, cgroup *configs.Cgroup) error {
	for _, prioMap := range cgroup.Resources.NetPrioIfpriomap {
		if err := fscommon.WriteFile(path, "net_prio.ifpriomap", prioMap.CgroupString()); err != nil {
			return err
		}
	}

	return nil
}

func (s *NetPrioGroup) GetStats(path string, stats *cgroups.Stats) error {
	return nil
}

func (s *NetPrioGroup) Clone(source, dest string) error {

	if err := fscommon.WriteFile(source, "cgroup.clone_children", "1"); err != nil {
		return err
	}

	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("Failed to create cgroup %s", dest)
	}

	return nil
}
