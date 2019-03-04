// +build linux

package cgroups

import (
	"fmt"

	"github.com/opencontainers/runc/libcontainer/configs"
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

	// The option func SystemdCgroups() and Cgroupfs() require following attributes:
	// 	Paths   map[string]string
	// 	Cgroups *configs.Cgroup
	// Paths maps cgroup subsystem to path at which it is mounted.
	// Cgroups specifies specific cgroup settings for the various subsystems

	// Returns cgroup paths to save in a state file and to be able to
	// restore the object later.
	GetPaths() map[string]string

	// Sets the cgroup as configured.
	Set(container *configs.Config) error

	// sysvisor-runc: creates a child cgroup for the system container's cgroup root;
	// we don't need a corresponding destroy method because the existing Destroy()
	// method will destroy the child cgroup.
	CreateChildCgroup(container *configs.Config) error

	// sysvisor-runc: applies child cgroup configuration to the process with the specified
	// pid. Must be called after Apply() has been called because Apply() configures
	// internal state in the cgroup manager that ApplyChildCgroup() does not. This
	// awkwardness could be avoided if this interface had a separate Create() method as
	// currently Apply() serves as both create and apply.
	ApplyChildCgroup(pid int) error

	// sysvisor-runc: same as GetPaths(), but returns child cgroup paths
	GetChildCgroupPaths() map[string]string
}

type NotFoundError struct {
	Subsystem string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("mountpoint for %s not found", e.Subsystem)
}

func NewNotFoundError(sub string) error {
	return &NotFoundError{
		Subsystem: sub,
	}
}

func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*NotFoundError)
	return ok
}
