// +build linux

package fs

import (
	"fmt"
	"os"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	"github.com/opencontainers/runc/libcontainer/configs"
)

type NameGroup struct {
	GroupName string
	Join      bool
}

func (s *NameGroup) Name() string {
	return s.GroupName
}

func (s *NameGroup) Apply(path string, d *cgroupData) error {
	if s.Join {
		// ignore errors if the named cgroup does not exist
		join(path, d.pid)
	}
	return nil
}

func (s *NameGroup) Set(path string, cgroup *configs.Cgroup) error {
	return nil
}

func (s *NameGroup) GetStats(path string, stats *cgroups.Stats) error {
	return nil
}

func (s *NameGroup) Clone(source, dest string) error {

	if err := fscommon.WriteFile(source, "cgroup.clone_children", "1"); err != nil {
		return err
	}

	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("Failed to create cgroup %s", dest)
	}

	return nil
}
