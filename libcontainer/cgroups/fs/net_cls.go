// +build linux

package fs

import (
	"fmt"
	"os"
	"strconv"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	"github.com/opencontainers/runc/libcontainer/configs"
)

type NetClsGroup struct {
}

func (s *NetClsGroup) Name() string {
	return "net_cls"
}

func (s *NetClsGroup) Apply(path string, d *cgroupData) error {
	return join(path, d.pid)
}

func (s *NetClsGroup) Set(path string, cgroup *configs.Cgroup) error {
	if cgroup.Resources.NetClsClassid != 0 {
		if err := fscommon.WriteFile(path, "net_cls.classid", strconv.FormatUint(uint64(cgroup.Resources.NetClsClassid), 10)); err != nil {
			return err
		}
	}

	return nil
}

func (s *NetClsGroup) GetStats(path string, stats *cgroups.Stats) error {
	return nil
}

func (s *NetClsGroup) Clone(source, dest string) error {

	if err := fscommon.WriteFile(source, "cgroup.clone_children", "1"); err != nil {
		return err
	}

	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("Failed to create cgroup %s", dest)
	}

	return nil
}
