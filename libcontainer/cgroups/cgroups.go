// +build linux

package cgroups

import (
	"github.com/opencontainers/runc/libcontainer/configs"
)

// syscontCgroupRoot is the name of the host's cgroup subtree that is exposed /
// delegated inside the system container. This subtree lives under the cgroup
// hierarchy associated with the container itself. For example:
//
// /sys/fs/cgroup/<cgroup-controller>/docker/<container-id>/syscont-group-root

var SyscontCgroupRoot string = "syscont-cgroup-root"

type CgroupType int

const (
	Cgroup_v1_fs CgroupType = iota
	Cgroup_v1_systemd
	Cgroup_v2_fs
	Cgroup_v2_systemd
)

type Manager interface {
	// Applies cgroup configuration to the process with the specified pid
	Apply(pid int) error

	// Returns the PIDs inside the cgroup set
	GetPids() ([]int, error)

	// Returns the PIDs inside the cgroup set & all sub-cgroups
	GetAllPids() ([]int, error)

	// Returns statistics for the cgroup set
	GetStats() (*Stats, error)

	// Toggles the freezer cgroup according with specified state
	Freeze(state configs.FreezerState) error

	// Destroys the cgroup set & all sub-cgroups
	Destroy() error

	// Path returns a cgroup path to the specified controller/subsystem.
	// For cgroupv2, the argument is unused and can be empty.
	Path(string) string

	// Sets the cgroup as configured.
	Set(container *configs.Config) error

	// GetPaths returns cgroup path(s) to save in a state file in order to restore later.
	//
	// For cgroup v1, a key is cgroup subsystem name, and the value is the path
	// to the cgroup for this subsystem.
	//
	// For cgroup v2 unified hierarchy, a key is "", and the value is the unified path.
	GetPaths() map[string]string

	// GetCgroups returns the cgroup data as configured.
	GetCgroups() (*configs.Cgroup, error)

	// GetFreezerState retrieves the current FreezerState of the cgroup.
	GetFreezerState() (configs.FreezerState, error)

	// Whether the cgroup path exists or not
	Exists() bool

	// sysbox-runc: creates a child cgroup that will serve as the cgroup root
	// exposed inside the system container. We don't need a corresponding
	// destroy method because the existing Destroy() method will destroy the
	// child cgroup.
	CreateChildCgroup(container *configs.Config) error

	// sysbox-runc: applies child cgroup configuration to the process with the specified
	// pid. Must be called after Apply() has been called because Apply() configures
	// internal state in the cgroup manager that ApplyChildCgroup() does not. This
	// awkwardness could be avoided if this interface had a separate Create() method as
	// currently Apply() serves as both create and apply.
	ApplyChildCgroup(pid int) error

	// sysbox-runc: same as GetPaths(), but returns child cgroup paths
	GetChildCgroupPaths() map[string]string

	// sysbox-runc: get the type of the cgroup manager
	GetType() CgroupType
}
