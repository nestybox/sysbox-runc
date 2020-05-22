package libcontainer

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/selinux/go-selinux/label"
	"golang.org/x/sys/unix"
)

type linuxRootfsInit struct {
	pipe *os.File
	reqs []opReq
}

// getDir returns the path to the directory that contains the file at the given path
func getDir(file string) (string, error) {
	fi, err := os.Stat(file)
	if err != nil {
		return "", fmt.Errorf("stat %s: %v", file, err)
	}
	if !fi.IsDir() {
		return filepath.Dir(file), nil
	} else {
		return file, nil
	}
}

func doBindMount(m *configs.Mount) error {

	// sysbox-runc: For some reason, when the rootfs is on shiftfs, we
	// need to do an Lstat() of the destination path prior to doing the
	// mount. Otherwise we get a "permission denied" error. It took me
	// a while to figure this out. I found out by noticing that the
	// mount cmd (not the syscall) would not hit the permission error,
	// and then did an strace of the syscalls being done by the mount
	// command, which led me to realize that the Lstat() was solving
	// the problem. FYI, in order to do the strace, I had to enable the
	// ptrace syscall inside the container (via the libsysbox's syscalls.go).

	_, err := os.Lstat(filepath.Dir(m.Source))
	if err != nil {
		return err
	}

	if err := unix.Mount(m.Source, m.Destination, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind-mount of %s to %s failed: %v", m.Source, m.Destination, err)
	}

	for _, pflag := range m.PropagationFlags {
		if err := unix.Mount("", m.Destination, "", uintptr(pflag), ""); err != nil {
			return err
		}
	}

	return nil
}

// Creates an alias for the Docker DNS via iptables.
func doDockerDnsSwitch(oldDns, newDns string) error {
	var cmdOut, cmdErr bytes.Buffer

	// Get current iptables
	cmd := exec.Command("/usr/sbin/iptables-save")
	cmd.Stdout = &cmdOut
	cmd.Stderr = &cmdErr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start %v: %s", cmd.Args, err)
	}

	// Create the alias for the Docker DNS (it's at oldDns (e.g., 127.0.0.11),
	// but we will alias it to newDns (e.g., 172.20.0.1)).
	//
	// That is, inside the container, all processes will think the Docker DNS is
	// at newDns, but iptables will send the packet to oldDns. Similarly, when
	// oldDns responds, iptables will make it seem like newDns is responding.

	iptables := cmdOut.String()

	// All packets destined to oldDns now go to newDns
	iptables = strings.Replace(iptables, fmt.Sprintf("-d %s", oldDns), fmt.Sprintf("-d %s", newDns), -1)

	// Source NATing from oldDns is now from newDns
	iptables = strings.Replace(iptables, "--to-source :53", fmt.Sprintf("--to-source %s:53", newDns), -1)

	// Add pre-routing rule so that packets from inner containers go through DOCKER_OUTPUT rule (DNAT)
	rule := fmt.Sprintf("-A OUTPUT -d %s/32 -j DOCKER_OUTPUT", newDns)
	newRule := rule + "\n" + fmt.Sprintf("-A PREROUTING -d %s/32 -j DOCKER_OUTPUT", newDns)
	iptables = strings.Replace(iptables, rule, newRule, 1)

	// Commit the changed iptables
	cmd = exec.Command("/usr/sbin/iptables-restore")
	cmd.Stdin = strings.NewReader(iptables)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start %v: %s", cmd.Args, err)
	}

	return nil
}

// sysbox-runc:
// Init performs container rootfs initialization actions from within the container's mount
// namespace only. By virtue of only entering the mount namespace, Init has true
// root-level access to the host and thus can perform operations that the container's init
// process is not allowed to.
func (l *linuxRootfsInit) Init() error {

	if len(l.reqs) == 0 {
		return newSystemError(fmt.Errorf("no op requests!"))
	}

	// If multiple requests are passed in the slice, they must all be
	// of the same type.

	switch l.reqs[0].Op {
	case bind:

		// The mount requests assume that the process cwd be the rootfs directory
		rootfs := l.reqs[0].Rootfs
		if err := unix.Chdir(rootfs); err != nil {
			return newSystemErrorWithCausef(err, "chdir to rootfs %s", rootfs)
		}

		for _, req := range l.reqs {
			m := &req.Mount
			mountLabel := req.Label

			if err := doBindMount(m); err != nil {
				return newSystemErrorWithCausef(err, "bind mounting %s to %s", m.Source, m.Destination)
			}

			// The bind mount won't change mount options, we need remount to make mount options effective.
			// first check that we have non-default options required before attempting a remount
			if m.Flags&^(unix.MS_REC|unix.MS_REMOUNT|unix.MS_BIND) != 0 {
				// only remount if unique mount options are set
				if err := remount(m); err != nil {
					return newSystemErrorWithCausef(err, "remount %s to %s", m.Source, m.Destination)
				}
			}

			// Apply label
			if m.Relabel != "" {
				if err := label.Validate(m.Relabel); err != nil {
					return newSystemErrorWithCausef(err, "validating label %s", m.Relabel)
				}
				shared := label.IsShared(m.Relabel)
				if err := label.Relabel(m.Source, mountLabel, shared); err != nil {
					return newSystemErrorWithCausef(err, "relabeling %s to %s", m.Source, mountLabel)
				}
			}
		}

	case switchDockerDns:
		oldDns := l.reqs[0].OldDns
		newDns := l.reqs[0].NewDns

		if err := doDockerDnsSwitch(oldDns, newDns); err != nil {
			return newSystemErrorWithCausef(err, "Docker DNS switch from %s to %s", oldDns, newDns)
		}

	default:
		return newSystemError(fmt.Errorf("invalid init type"))
	}

	if err := writeSync(l.pipe, opDone); err != nil {
		return err
	}

	l.pipe.Close()
	return nil
}
