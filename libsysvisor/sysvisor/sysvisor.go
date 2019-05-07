package sysvisor

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
	"golang.org/x/sys/unix"
)

// The kernel release is chosen based on whether it contains all kernel fixes required
// to run sysvisor. Refer to the sysvisor github issues and search for "kernel".
var minSupportedKernel = []int{4, 10} // 4.10

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

// GetKernelRelease returns the kernel release (e.g., "4.18")
func GetKernelRelease() (string, error) {
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return "", fmt.Errorf("uname: %v", err)
	}
	n := bytes.IndexByte(utsname.Release[:], 0)
	return string(utsname.Release[:n]), nil
}

// checkKernelRelease checks if the host has a Linux kernel supported by Sysvisor.
func checkKernelRelease() error {
	kernelRel, err := GetKernelRelease()
	if err != nil {
		return err
	}

	// compare the major.minor numbers only

	splits := strings.SplitN(kernelRel, ".", -1)
	if len(splits) < 2 {
		return fmt.Errorf("failed to parse kernel release %v", kernelRel)
	}

	supported := true
	for i := 0; i < 2; i++ {
		num, err := strconv.Atoi(splits[0])
		if err != nil {
			return fmt.Errorf("failed to parse kernel release %v", kernelRel)
		}
		if num < minSupportedKernel[i] {
			supported = false
		}
	}

	if !supported {
		rel := []string{}
		rel = append(rel, strconv.Itoa(minSupportedKernel[0]))
		rel = append(rel, strconv.Itoa(minSupportedKernel[1]))
		return fmt.Errorf("kernel release %v is not supported; need >= %v", kernelRel, strings.Join(rel, "."))
	}

	return nil
}

// CheckHostConfig checks if the host is configured appropriately to run sysvisor-runc
func CheckHostConfig(context *cli.Context) error {

	if !context.GlobalBool("no-kernel-check") {
		if err := checkKernelRelease(); err != nil {
			return fmt.Errorf("host is not configured properly: %v", err)
		}
	}

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
