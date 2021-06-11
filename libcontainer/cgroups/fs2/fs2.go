// +build linux

package fs2

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/pkg/errors"
)

type manager struct {
	config *configs.Cgroup
	// dirPath is like "/sys/fs/cgroup/user.slice/user-1001.slice/session-1.scope"
	dirPath string
	// controllers is content of "cgroup.controllers" file.
	// excludes pseudo-controllers ("devices" and "freezer").
	controllers map[string]struct{}
	rootless    bool
}

// NewManager creates a manager for cgroup v2 unified hierarchy.
// dirPath is like "/sys/fs/cgroup/user.slice/user-1001.slice/session-1.scope".
// If dirPath is empty, it is automatically set using config.
func NewManager(config *configs.Cgroup, dirPath string, rootless bool) (cgroups.Manager, error) {
	if config == nil {
		config = &configs.Cgroup{}
	}
	if dirPath == "" {
		var err error
		dirPath, err = defaultDirPath(config)
		if err != nil {
			return nil, err
		}
	}

	m := &manager{
		config:   config,
		dirPath:  dirPath,
		rootless: rootless,
	}
	return m, nil
}

func (m *manager) getControllers() error {
	if m.controllers != nil {
		return nil
	}

	data, err := fscommon.ReadFile(m.dirPath, "cgroup.controllers")
	if err != nil {
		if m.rootless && m.config.Path == "" {
			return nil
		}
		return err
	}
	fields := strings.Fields(data)
	m.controllers = make(map[string]struct{}, len(fields))
	for _, c := range fields {
		m.controllers[c] = struct{}{}
	}

	return nil
}

func (m *manager) Apply(pid int) error {
	if err := CreateCgroupPath(m.dirPath, m.config); err != nil {
		// Related tests:
		// - "runc create (no limits + no cgrouppath + no permission) succeeds"
		// - "runc create (rootless + no limits + cgrouppath + no permission) fails with permission error"
		// - "runc create (rootless + limits + no cgrouppath + no permission) fails with informative error"
		if m.rootless {
			if m.config.Path == "" {
				if blNeed, nErr := needAnyControllers(m.config); nErr == nil && !blNeed {
					return nil
				}
				return errors.Wrap(err, "rootless needs no limits + no cgrouppath when no permission is granted for cgroups")
			}
		}
		return err
	}
	if err := cgroups.WriteCgroupProc(m.dirPath, pid); err != nil {
		return err
	}
	return nil
}

func (m *manager) GetPids() ([]int, error) {
	return cgroups.GetPids(m.dirPath)
}

func (m *manager) GetAllPids() ([]int, error) {
	return cgroups.GetAllPids(m.dirPath)
}

func (m *manager) GetStats() (*cgroups.Stats, error) {
	var (
		errs []error
	)

	st := cgroups.NewStats()
	if err := m.getControllers(); err != nil {
		return st, err
	}

	// pids (since kernel 4.5)
	if _, ok := m.controllers["pids"]; ok {
		if err := statPids(m.dirPath, st); err != nil {
			errs = append(errs, err)
		}
	} else {
		if err := statPidsWithoutController(m.dirPath, st); err != nil {
			errs = append(errs, err)
		}
	}
	// memory (since kernel 4.5)
	if _, ok := m.controllers["memory"]; ok {
		if err := statMemory(m.dirPath, st); err != nil {
			errs = append(errs, err)
		}
	}
	// io (since kernel 4.5)
	if _, ok := m.controllers["io"]; ok {
		if err := statIo(m.dirPath, st); err != nil {
			errs = append(errs, err)
		}
	}
	// cpu (since kernel 4.15)
	if _, ok := m.controllers["cpu"]; ok {
		if err := statCpu(m.dirPath, st); err != nil {
			errs = append(errs, err)
		}
	}
	// hugetlb (since kernel 5.6)
	if _, ok := m.controllers["hugetlb"]; ok {
		if err := statHugeTlb(m.dirPath, st); err != nil {
			errs = append(errs, err)
		}
	}
	// rdma (since kernel 4.11)
	if err := fscommon.RdmaGetStats(m.dirPath, st); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	if len(errs) > 0 && !m.rootless {
		return st, errors.Errorf("error while statting cgroup v2: %+v", errs)
	}
	return st, nil
}

func (m *manager) Freeze(state configs.FreezerState) error {
	if err := setFreezer(m.dirPath, state); err != nil {
		return err
	}
	m.config.Resources.Freezer = state
	return nil
}

func (m *manager) Destroy() error {
	return cgroups.RemovePath(m.dirPath)
}

func (m *manager) Path(_ string) string {
	return m.dirPath
}

func (m *manager) Set(container *configs.Config) error {
	if container == nil || container.Cgroups == nil {
		return nil
	}
	if err := m.getControllers(); err != nil {
		return err
	}
	// pids (since kernel 4.5)
	if err := setPids(m.dirPath, container.Cgroups); err != nil {
		return err
	}
	// memory (since kernel 4.5)
	if err := setMemory(m.dirPath, container.Cgroups); err != nil {
		return err
	}
	// io (since kernel 4.5)
	if err := setIo(m.dirPath, container.Cgroups); err != nil {
		return err
	}
	// cpu (since kernel 4.15)
	if err := setCpu(m.dirPath, container.Cgroups); err != nil {
		return err
	}
	// devices (since kernel 4.15, pseudo-controller)
	//
	// When m.Rootless is true, errors from the device subsystem are ignored because it is really not expected to work.
	// However, errors from other subsystems are not ignored.
	// see @test "runc create (rootless + limits + no cgrouppath + no permission) fails with informative error"
	if err := setDevices(m.dirPath, container.Cgroups); err != nil && !m.rootless {
		return err
	}
	// cpuset (since kernel 5.0)
	if err := setCpuset(m.dirPath, container.Cgroups); err != nil {
		return err
	}
	// hugetlb (since kernel 5.6)
	if err := setHugeTlb(m.dirPath, container.Cgroups); err != nil {
		return err
	}
	// rdma (since kernel 4.11)
	if err := fscommon.RdmaSet(m.dirPath, container.Cgroups); err != nil {
		return err
	}
	// freezer (since kernel 5.2, pseudo-controller)
	if err := setFreezer(m.dirPath, container.Cgroups.Freezer); err != nil {
		return err
	}
	if err := m.setUnified(container.Cgroups.Unified); err != nil {
		return err
	}
	m.config = container.Cgroups
	return nil
}

func (m *manager) setUnified(res map[string]string) error {
	for k, v := range res {
		if strings.Contains(k, "/") {
			return fmt.Errorf("unified resource %q must be a file name (no slashes)", k)
		}
		if err := fscommon.WriteFile(m.dirPath, k, v); err != nil {
			errC := errors.Cause(err)
			// Check for both EPERM and ENOENT since O_CREAT is used by WriteFile.
			if errors.Is(errC, os.ErrPermission) || errors.Is(errC, os.ErrNotExist) {
				// Check if a controller is available,
				// to give more specific error if not.
				sk := strings.SplitN(k, ".", 2)
				if len(sk) != 2 {
					return fmt.Errorf("unified resource %q must be in the form CONTROLLER.PARAMETER", k)
				}
				c := sk[0]
				if _, ok := m.controllers[c]; !ok && c != "cgroup" {
					return fmt.Errorf("unified resource %q can't be set: controller %q not available", k, c)
				}
			}
			return errors.Wrapf(err, "can't set unified resource %q", k)
		}
	}

	return nil
}

func (m *manager) GetPaths() map[string]string {
	paths := make(map[string]string, 1)
	paths[""] = m.dirPath
	return paths
}

func (m *manager) GetCgroups() (*configs.Cgroup, error) {
	return m.config, nil
}

func (m *manager) GetFreezerState() (configs.FreezerState, error) {
	return getFreezer(m.dirPath)
}

func (m *manager) Exists() bool {
	return cgroups.PathExists(m.dirPath)
}

func (m *manager) CreateChildCgroup(config *configs.Config) error {

	// Change the cgroup ownership to match the root user in the system
	// container (needed for delegation).
	path := m.dirPath

	rootuid, err := config.HostRootUID()
	if err != nil {
		return err
	}
	rootgid, err := config.HostRootGID()
	if err != nil {
		return err
	}

	if err := os.Chown(path, rootuid, rootgid); err != nil {
		return fmt.Errorf("Failed to change owner of cgroup %s", path)
	}

	// Change ownership of some of the files inside the sys container's cgroup;
	// for cgroups v2 we only change the ownership of a subset of the files, as
	// specified in section "Cgroups Delegation: Delegating a Hierarchy to a Less
	// Privileged User" in cgroups(7).
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	for _, file := range files {
		fname := file.Name()

		if fname == "cgroup.procs" ||
			fname == "cgroup.subtree_control" ||
			fname == "cgroup.threads" {

			absFileName := filepath.Join(path, fname)
			if err := os.Chown(absFileName, rootuid, rootgid); err != nil {
				return fmt.Errorf("Failed to change owner for file %s", absFileName)
			}
		}
	}

	// Create a leaf cgroup to be used for the sys container's init process (and
	// for all its child processes). Its purpose is to prevent processes from
	// living in the sys container's cgroup root, because once inner sub-cgroups
	// are created, the kernel considers the sys container's cgroup root an
	// intermediate node in the global cgroup hierarchy. This in turn forces all
	// sub-groups inside the sys container to be of "domain-invalid" type (and
	// thus prevents domain cgroup controllers such as the memory controller
	// from being applied inside the sys container).
	//
	// We choose the name "init.scope" for the leaf cgroup because it works well
	// in sys containers that carry systemd, as well as those that don't. In both
	// cases, the sys container's init processes are placed in the init.scope
	// cgroup. For sys container's with systemd, systemd then moves the processes
	// to other sub-cgroups it manages.
	//
	// Note that processes that enter the sys container via "exec" will also
	// be placed in this sub-cgroup.

	leafPath := filepath.Join(path, "init.scope")
	if err = os.MkdirAll(leafPath, 0755); err != nil {
		return err
	}

	if err := os.Chown(leafPath, rootuid, rootgid); err != nil {
		return fmt.Errorf("Failed to change owner of cgroup %s", leafPath)
	}

	files, err = ioutil.ReadDir(leafPath)
	if err != nil {
		return err
	}
	for _, file := range files {
		fname := file.Name()

		if fname == "cgroup.procs" ||
			fname == "cgroup.subtree_control" ||
			fname == "cgroup.threads" {

			absFileName := filepath.Join(leafPath, fname)
			if err := os.Chown(absFileName, rootuid, rootgid); err != nil {
				return fmt.Errorf("Failed to change owner for file %s", absFileName)
			}
		}
	}

	return nil
}

func (m *manager) ApplyChildCgroup(pid int) error {
	paths := make(map[string]string, 1)
	paths[""] = filepath.Join(m.dirPath, "init.scope")
	return cgroups.EnterPid(paths, pid)
}

func (m *manager) GetChildCgroupPaths() map[string]string {
	return m.GetPaths()
}

func (m *manager) GetType() cgroups.CgroupType {
	return cgroups.Cgroup_v2_fs
}
