package sysvisor

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// checkUnprivilegedUserns checks if the kernel is configured to allow
// unprivileged users to create namespaces. This is necessary for
// running containers inside a system container.
func checkUnprivilegedUserns() error {

	// Debian & Ubuntu
	path := "/proc/sys/kernel/unprivileged_userns_clone"
	if _, err := os.Stat(path); err == nil {

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		var b []byte = make([]byte, 8)
		_, err = f.Read(b)
		if err != nil {
			return err
		}

		var val int
		fmt.Sscanf(string(b), "%d", &val)

		if val != 1 {
			return fmt.Errorf("kernel is not configured to allow unprivileged users to create namespaces: %s: want 1, have %d", path, val)
		}
	}

	// TODO: add other distros
	// Fedora
	// CentOS
	// Arch
	// Alpine
	// Amazon

	return nil
}

// CheckHostConfig checks if the host is configured appropriately to run sysvisor-runc
func CheckHostConfig() error {
	if err := checkUnprivilegedUserns(); err != nil {
		return fmt.Errorf("host is not configured properly: %v", err)
	}

	// TODO: check for fuse module presence (needed by sysvisor-fs)

	return nil
}

// NeedUidShiftOnRootfs checks if uid/gid shifting on the container's rootfs is required to
// run the system container.
func NeedUidShiftOnRootfs(spec *specs.Spec) (bool, error) {
	var hostUidMap, hostGidMap uint32

	// the uid map is assumed to be present
	for _, mapping := range spec.Linux.UIDMappings {
		if mapping.ContainerID == 0 {
			hostUidMap = mapping.HostID
		}
	}

	// the gid map is assumed to be present
	for _, mapping := range spec.Linux.GIDMappings {
		if mapping.ContainerID == 0 {
			hostGidMap = mapping.HostID
		}
	}

	// find the rootfs owner
	rootfs := spec.Root.Path

	fi, err := os.Stat(rootfs)
	if err != nil {
		return false, err
	}

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("failed to convert to syscall.Stat_t")
	}

	rootfsUid := st.Uid
	rootfsGid := st.Gid

	// use shifting when the rootfs is owned by true root, the containers uid/gid root
	// mapping do not match the container's rootfs owner, and the host ID for the uid and
	// gid mappings is the same.
	if rootfsUid == 0 && rootfsGid == 0 &&
		hostUidMap != rootfsUid && hostGidMap != rootfsGid &&
		hostUidMap == hostGidMap {
		return true, nil
	}

	return false, nil
}

// KernelModSupported returns nil if the given module is loaded in the kernel.
func KernelModSupported(mod string) error {

	// Load the module (if present in directory /lib/modules/`uname -r`)
	exec.Command("modprobe", mod).Run()

	// Check if the module is in the kernel
	f, err := os.Open("/proc/filesystems")
	if err != nil {
		return fmt.Errorf("failed to open /proc/filesystems to check for %s module", mod)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		if strings.Contains(s.Text(), mod) {
			return nil
		}
	}

	return fmt.Errorf("%s module is not loaded in the kernel", mod)
}
