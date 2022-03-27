package mount

import (
	"fmt"
)

// GetMounts retrieves a list of mounts for the current running process.
func GetMounts() ([]*Info, error) {
	return parseMountTable()
}

// GetMountsPid retrieves a list of mounts for the 'pid' process.
func GetMountsPid(pid uint32) ([]*Info, error) {
	return parseMountTableForPid(pid)
}

func FindMount(mountpoint string, mounts []*Info) bool {
	for _, m := range mounts {
		if m.Mountpoint == mountpoint {
			return true
		}
	}
	return false
}

// MountedWithFs looks at /proc/self/mountinfo to determine if the specified
// mountpoint has been mounted with the given filesystem type.
func MountedWithFs(mountpoint string, fs string, mounts []*Info) (bool, error) {

	// Search the table for the mountpoint
	for _, m := range mounts {
		if m.Mountpoint == mountpoint && m.Fstype == fs {
			return true, nil
		}
	}
	return false, nil
}

// GetMountAt returns information about the given mountpoint.
func GetMountAt(mountpoint string, mounts []*Info) (*Info, error) {

	// Search the table for the given mountpoint
	for _, m := range mounts {
		if m.Mountpoint == mountpoint {
			return m, nil
		}
	}
	return nil, fmt.Errorf("%s is not a mountpoint", mountpoint)
}

// Converts the set of mount options (e.g., "rw", "nodev", etc.) to it's
// corresponding mount flags representation
func OptionsToFlags(opt []string) int {
	return optToFlag(opt)
}
