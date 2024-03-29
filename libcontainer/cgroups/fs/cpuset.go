// +build linux

package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/moby/sys/mountinfo"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	"github.com/opencontainers/runc/libcontainer/configs"
	libcontainerUtils "github.com/opencontainers/runc/libcontainer/utils"
	"github.com/pkg/errors"
)

type CpusetGroup struct {
}

func (s *CpusetGroup) Name() string {
	return "cpuset"
}

func (s *CpusetGroup) Apply(path string, d *cgroupData) error {
	return s.ApplyDir(path, d.config, d.pid)
}

func (s *CpusetGroup) Set(path string, cgroup *configs.Cgroup) error {
	if cgroup.Resources.CpusetCpus != "" {
		if err := fscommon.WriteFile(path, "cpuset.cpus", cgroup.Resources.CpusetCpus); err != nil {
			return err
		}
	}
	if cgroup.Resources.CpusetMems != "" {
		if err := fscommon.WriteFile(path, "cpuset.mems", cgroup.Resources.CpusetMems); err != nil {
			return err
		}
	}
	return nil
}

func (s *CpusetGroup) Clone(source, dest string) error {

	// For the cpuset cgroup, cloning is done by simply setting cgroup.clone_children on the source
	if err := fscommon.WriteFile(source, "cgroup.clone_children", "1"); err != nil {
		return err
	}

	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("Failed to create cgroup %s", dest)
	}

	return nil
}

func getCpusetStat(path string, filename string) ([]uint16, error) {
	var extracted []uint16
	fileContent, err := fscommon.GetCgroupParamString(path, filename)
	if err != nil {
		return extracted, err
	}
	if len(fileContent) == 0 {
		return extracted, fmt.Errorf("%s found to be empty", filepath.Join(path, filename))
	}

	for _, s := range strings.Split(fileContent, ",") {
		splitted := strings.SplitN(s, "-", 3)
		switch len(splitted) {
		case 3:
			return extracted, fmt.Errorf("invalid values in %s", filepath.Join(path, filename))
		case 2:
			min, err := strconv.ParseUint(splitted[0], 10, 16)
			if err != nil {
				return extracted, err
			}
			max, err := strconv.ParseUint(splitted[1], 10, 16)
			if err != nil {
				return extracted, err
			}
			if min > max {
				return extracted, fmt.Errorf("invalid values in %s", filepath.Join(path, filename))
			}
			for i := min; i <= max; i++ {
				extracted = append(extracted, uint16(i))
			}
		case 1:
			value, err := strconv.ParseUint(s, 10, 16)
			if err != nil {
				return extracted, err
			}
			extracted = append(extracted, uint16(value))
		}
	}

	return extracted, nil
}

func (s *CpusetGroup) GetStats(path string, stats *cgroups.Stats) error {
	var err error

	stats.CPUSetStats.CPUs, err = getCpusetStat(path, "cpuset.cpus")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	stats.CPUSetStats.CPUExclusive, err = fscommon.GetCgroupParamUint(path, "cpuset.cpu_exclusive")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	stats.CPUSetStats.Mems, err = getCpusetStat(path, "cpuset.mems")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	stats.CPUSetStats.MemHardwall, err = fscommon.GetCgroupParamUint(path, "cpuset.mem_hardwall")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	stats.CPUSetStats.MemExclusive, err = fscommon.GetCgroupParamUint(path, "cpuset.mem_exclusive")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	stats.CPUSetStats.MemoryMigrate, err = fscommon.GetCgroupParamUint(path, "cpuset.memory_migrate")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	stats.CPUSetStats.MemorySpreadPage, err = fscommon.GetCgroupParamUint(path, "cpuset.memory_spread_page")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	stats.CPUSetStats.MemorySpreadSlab, err = fscommon.GetCgroupParamUint(path, "cpuset.memory_spread_slab")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	stats.CPUSetStats.MemoryPressure, err = fscommon.GetCgroupParamUint(path, "cpuset.memory_pressure")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	stats.CPUSetStats.SchedLoadBalance, err = fscommon.GetCgroupParamUint(path, "cpuset.sched_load_balance")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	stats.CPUSetStats.SchedRelaxDomainLevel, err = fscommon.GetCgroupParamInt(path, "cpuset.sched_relax_domain_level")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return nil
}

// Get the source mount point of directory passed in as argument.
func getMount(dir string) (string, error) {
	mi, err := mountinfo.GetMounts(mountinfo.ParentsFilter(dir))
	if err != nil {
		return "", err
	}
	if len(mi) < 1 {
		return "", errors.Errorf("Can't find mount point of %s", dir)
	}

	// find the longest mount point
	var idx, maxlen int
	for i := range mi {
		if len(mi[i].Mountpoint) > maxlen {
			maxlen = len(mi[i].Mountpoint)
			idx = i
		}
	}

	return mi[idx].Mountpoint, nil
}

func (s *CpusetGroup) ApplyDir(dir string, cgroup *configs.Cgroup, pid int) error {
	// This might happen if we have no cpuset cgroup mounted.
	// Just do nothing and don't fail.
	if dir == "" {
		return nil
	}
	root, err := getMount(dir)
	if err != nil {
		return err
	}
	root = filepath.Dir(root)
	// 'ensureParent' start with parent because we don't want to
	// explicitly inherit from parent, it could conflict with
	// 'cpuset.cpu_exclusive'.
	if err := cpusetEnsureParent(filepath.Dir(dir), root); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	// We didn't inherit cpuset configs from parent, but we have
	// to ensure cpuset configs are set before moving task into the
	// cgroup.
	// The logic is, if user specified cpuset configs, use these
	// specified configs, otherwise, inherit from parent. This makes
	// cpuset configs work correctly with 'cpuset.cpu_exclusive', and
	// keep backward compatibility.
	if err := s.ensureCpusAndMems(dir, cgroup); err != nil {
		return err
	}

	// because we are not using d.join we need to place the pid into the procs file
	// unlike the other subsystems
	return cgroups.WriteCgroupProc(dir, pid)
}

func getCpusetSubsystemSettings(parent string) (cpus, mems string, err error) {
	if cpus, err = fscommon.ReadFile(parent, "cpuset.cpus"); err != nil {
		return
	}
	if mems, err = fscommon.ReadFile(parent, "cpuset.mems"); err != nil {
		return
	}
	return cpus, mems, nil
}

// cpusetEnsureParent makes sure that the parent directory of current is created
// and populated with the proper cpus and mems files copied from
// its parent.
func cpusetEnsureParent(current, root string) error {
	parent := filepath.Dir(current)
	if libcontainerUtils.CleanPath(parent) == root {
		return nil
	}
	// Avoid infinite recursion.
	if parent == current {
		return errors.New("cpuset: cgroup parent path outside cgroup root")
	}
	if err := cpusetEnsureParent(parent, root); err != nil {
		return err
	}
	if err := os.MkdirAll(current, 0755); err != nil {
		return err
	}
	return cpusetCopyIfNeeded(current, parent)
}

// cpusetCopyIfNeeded copies the cpuset.cpus and cpuset.mems from the parent
// directory to the current directory if the file's contents are 0
func cpusetCopyIfNeeded(current, parent string) error {
	currentCpus, currentMems, err := getCpusetSubsystemSettings(current)
	if err != nil {
		return err
	}
	parentCpus, parentMems, err := getCpusetSubsystemSettings(parent)
	if err != nil {
		return err
	}

	if isEmptyCpuset(currentCpus) {
		if err := fscommon.WriteFile(current, "cpuset.cpus", string(parentCpus)); err != nil {
			return err
		}
	}
	if isEmptyCpuset(currentMems) {
		if err := fscommon.WriteFile(current, "cpuset.mems", string(parentMems)); err != nil {
			return err
		}
	}
	return nil
}

func isEmptyCpuset(str string) bool {
	return str == "" || str == "\n"
}

func (s *CpusetGroup) ensureCpusAndMems(path string, cgroup *configs.Cgroup) error {
	if err := s.Set(path, cgroup); err != nil {
		return err
	}
	return cpusetCopyIfNeeded(path, filepath.Dir(path))
}
