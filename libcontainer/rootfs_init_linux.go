package libcontainer

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	securejoin "github.com/cyphar/filepath-securejoin"
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

// iptablesRestoreHasWait determines if the version of iptables-restore on the
// host has "--wait" option.
func iptablesRestoreHasWait() (bool, error) {
	var cmd *exec.Cmd

	if _, err := os.Stat("/usr/sbin/iptables"); os.IsNotExist(err) {
		cmd = exec.Command("/sbin/iptables", "--version")
	} else {
		cmd = exec.Command("/usr/sbin/iptables", "--version")
	}

	bytes, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to start %v: %s", cmd.Args, err)
	}

	// output is "iptables <version>"; we are looking for version >= v1.6.2
	output := strings.Fields(string(bytes))
	if len(output) < 2 {
		return false, fmt.Errorf("failed to get iptables version: got %v", output)
	}

	// The iptables "--wait" option shows up in v1.6.2 and above
	// (see iptables commit 999eaa241212d3952ddff39a99d0d55a74e3639e on 03/16/2017)

	verStr := strings.TrimPrefix(output[1], "v")

	verConstraint, _ := semver.NewConstraint(">= 1.6.2")

	ver, err := semver.NewVersion(verStr)
	if err != nil {
		return false, fmt.Errorf("failed to parse iptables version: %s", err)
	}

	return verConstraint.Check(ver), nil
}

func doBindMount(m *configs.Mount) error {

	// sysbox-runc: For some reason, when the rootfs is on shiftfs, we
	// need to do an Lstat() of the source path prior to doing the
	// mount. Otherwise we get a "permission denied" error. It took me
	// a while to figure this out. I found out by noticing that the
	// mount cmd (not the syscall) would not hit the permission error,
	// and then did an strace of the syscalls being done by the mount
	// command, which led me to realize that the Lstat() was solving
	// the problem. FYI, in order to do the strace, I had to enable the
	// ptrace syscall inside the container (via the libsysbox's syscalls.go).

	src := m.Source
	if !m.BindSrcInfo.IsDir {
		src = filepath.Dir(m.Source)
	}

	os.Lstat(src)
	if err := unix.Mount(m.Source, m.Destination, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {

		// We've noticed that the lstat and/or mount syscall fails with EPERM when
		// bind-mounting a source dir that is on a shiftfs mount on top of a tmpfs
		// mount. For some reason the Linux "mount" command does not fail in this case,
		// so let's try it.

		cmd := exec.Command("/bin/mount", "--rbind", m.Source, m.Destination)
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("bind-mount of %s to %s failed: %v", m.Source, m.Destination, err)
		}
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
	var (
		cmdOut, cmdErr bytes.Buffer
		cmd            *exec.Cmd
	)

	// Get current iptables
	if _, err := os.Stat("/usr/sbin/iptables-save"); os.IsNotExist(err) {
		cmd = exec.Command("/sbin/iptables-save")
	} else {
		cmd = exec.Command("/usr/sbin/iptables-save")
	}

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
	//
	// The iptables-restore command holds the xtables lock to ensure consistency
	// in case multiple processes try to restore iptables concurrently. Recent
	// versions of this command (e.g., iptables 1.8.3) support the "--wait" flag
	// to deal with xtables lock contention. However, older versions (e.g.,
	// iptables 1.6.1) don't. For those older versions, we do the wait ourselves.

	xtablesWait := 30             // wait up to 30 secs for the xtables lock
	xtablesWaitInterval := 100000 // poll the lock every 100ms when waiting

	iptablesRestoreHasWait, err := iptablesRestoreHasWait()
	if err != nil {
		return err
	}

	iptablesRestorePath := "/usr/sbin/iptables-restore"
	if _, err = os.Stat(iptablesRestorePath); os.IsNotExist(err) {
		iptablesRestorePath = "/sbin/iptables-restore"
	}

	if iptablesRestoreHasWait {

		wait := strconv.Itoa(xtablesWait)
		waitInterval := strconv.Itoa(xtablesWaitInterval)

		cmd = exec.Command(iptablesRestorePath, "--wait", wait, "--wait-interval", waitInterval)
		cmd.Stdin = strings.NewReader(iptables)

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to start %v: %s", cmd.Args, err)
		}

	} else {

		// If we are here, iptables-restore is old and does not support concurrent
		// accesses (does not have the "--wait") option. This means that if
		// multiple processes do iptables-restore concurrently, the command may
		// return exit status "4" (resource unavailable) (see iptables/include/xtables.h).
		// Here we do our best to deal with this by retrying the operation whenever
		// we get this error.

		var err error

		exitCodeResourceUnavailable := 4
		success := false

		for start := time.Now(); time.Since(start) < (time.Duration(xtablesWait) * time.Second); {

			cmd = exec.Command(iptablesRestorePath)
			cmd.Stdin = strings.NewReader(iptables)

			err := cmd.Run()
			if err == nil {
				success = true
				break
			}

			if exitError, ok := err.(*exec.ExitError); ok {
				exitCode := exitError.ExitCode()
				if exitCode != exitCodeResourceUnavailable {
					break
				}
			}

			time.Sleep(time.Duration(xtablesWaitInterval) * time.Microsecond)
		}

		if !success {
			return fmt.Errorf("failed to run %v: %s", cmd.Args, err)
		}
	}

	return nil
}

// sysbox-runc:
// Init performs container's rootfs initialization actions from within specific
// container namespaces. By virtue of entering to an individual namespace (i.e.
// 'mount' or 'network' ns), Init has true root-level access to the host and thus
// can perform operations that the container's init process is not allowed to.
func (l *linuxRootfsInit) Init() error {

	if len(l.reqs) == 0 {
		return newSystemError(fmt.Errorf("no op requests!"))
	}

	// If multiple requests are passed in the slice, they must all be
	// of the same type.

	switch l.reqs[0].Op {

	case bind:
		// The mount requests assume that the process cwd is the rootfs directory
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
					return newSystemErrorWithCausef(err, "remount of %s with flags %#x",
						m.Destination, m.Flags)
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

	case chown:
		rootfs := l.reqs[0].Rootfs

		for _, req := range l.reqs {
			path, err := securejoin.SecureJoin(rootfs, req.Path)
			if err != nil {
				return newSystemErrorWithCausef(err, "secure join of %s and %s failed: %s", rootfs, req.Path, err)
			}

			uid := req.Uid
			gid := req.Gid

			if err := unix.Chown(path, uid, gid); err != nil {
				return newSystemErrorWithCausef(err, "failed to chown %s to %v:%v", path, uid, gid)
			}
		}

	case mkdir:
		rootfs := l.reqs[0].Rootfs

		for _, req := range l.reqs {
			path, err := securejoin.SecureJoin(rootfs, req.Path)
			if err != nil {
				return newSystemErrorWithCausef(err, "secure join of %s and %s failed: %s", rootfs, req.Path, err)
			}

			mode := req.Mode
			uid := req.Uid
			gid := req.Gid

			if err := os.MkdirAll(path, mode); err != nil {
				return newSystemErrorWithCausef(err, "failed to mkdirall %s: %s", path, err)
			}
			if err := unix.Chown(path, uid, gid); err != nil {
				return newSystemErrorWithCausef(err, "failed to chown %s to %v:%v", path, uid, gid)
			}

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
