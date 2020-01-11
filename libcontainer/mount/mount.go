package mount

import (
	"fmt"
)

// GetMounts retrieves a list of mounts for the current running process.
func GetMounts() ([]*Info, error) {
	return parseMountTable()
}

// GetMounts retrieves a list of mounts for the 'pid' process.
func GetMountsForPid(pid uint32) ([]*Info, error) {
	return parseMountTableForPid(pid)
}

// Mounted looks at /proc/self/mountinfo to determine if the specified
// mountpoint has been mounted
func Mounted(mountpoint string) (bool, error) {
	entries, err := parseMountTable()
	if err != nil {
		return false, err
	}

	// Search the table for the mountpoint
	for _, e := range entries {
		if e.Mountpoint == mountpoint {
			return true, nil
		}
	}
	return false, nil
}

// MountedWithFs looks at /proc/self/mountinfo to determine if the specified
// mountpoint has been mounted with the given filesystem type.
func MountedWithFs(mountpoint string, fs string) (bool, error) {
	entries, err := parseMountTable()
	if err != nil {
		return false, err
	}

	// Search the table for the mountpoint
	for _, e := range entries {
		if e.Mountpoint == mountpoint && e.Fstype == fs {
			return true, nil
		}
	}
	return false, nil
}

// GetMountAt returns information about the given mountpoint.
func GetMountAt(mountpoint string) (*Info, error) {
	entries, err := parseMountTable()
	if err != nil {
		return nil, err
	}
	// Search the table for the given mountpoint
	for _, e := range entries {
		if e.Mountpoint == mountpoint {
			return e, nil
		}
	}
	return nil, fmt.Errorf("%s is not a mountpoint", mountpoint)
}

// GetMountAt returns information about the given mountpoint and pid.
func GetMountAtForPid(pid uint32, mountpoint string) (*Info, error) {
	entries, err := parseMountTableForPid(pid)
	if err != nil {
		return nil, err
	}

	// Search the table for the given mountpoint.
	for _, e := range entries {
		if e.Mountpoint == mountpoint {
			return e, nil
		}
	}
	return nil, fmt.Errorf("%s is not a mountpoint", mountpoint)
}
