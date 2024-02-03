//go:build linux
// +build linux

package libcontainer

import (
	"os"
	"runtime"

	"github.com/opencontainers/runc/libcontainer/apparmor"
	"github.com/opencontainers/runc/libcontainer/keys"
	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/selinux/go-selinux"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// linuxSetnsInit performs the container's initialization for running a new process
// inside an existing container.
type linuxSetnsInit struct {
	pipe          *os.File
	consoleSocket *os.File
	config        *initConfig
}

func (l *linuxSetnsInit) getSessionRingName() string {
	return "_ses." + l.config.ContainerId
}

func (l *linuxSetnsInit) Init() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if !l.config.Config.NoNewKeyring {
		if err := selinux.SetKeyLabel(l.config.ProcessLabel); err != nil {
			return err
		}
		defer selinux.SetKeyLabel("")
		// Do not inherit the parent's session keyring.
		if _, err := keys.JoinSessionKeyring(l.getSessionRingName()); err != nil {
			// Same justification as in standart_init_linux.go as to why we
			// don't bail on ENOSYS.
			//
			// TODO(cyphar): And we should have logging here too.
			if errors.Cause(err) != unix.ENOSYS {
				return errors.Wrap(err, "join session keyring")
			}
		}
	}
	if l.config.CreateConsole {
		if err := setupConsole(l.consoleSocket, l.config, false); err != nil {
			return err
		}
		if err := system.Setctty(); err != nil {
			return err
		}
	}
	if l.config.NoNewPrivileges {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return err
		}
	}
	if err := selinux.SetExecLabel(l.config.ProcessLabel); err != nil {
		return err
	}
	defer selinux.SetExecLabel("")

	// Normally we enable seccomp just before exec'ing into the sys container's so as few
	// syscalls take place after enabling seccomp. However, if the process does not have
	// CAP_SYS_ADMIN (e.g., the process is non-root) and NoNewPrivileges is cleared, then
	// we must enable seccomp here (before we drop the process caps in finalizeNamespace()
	// below). Otherwise we get a permission denied error.

	seccompNotifDone := false
	seccompFiltDone := false

	if !l.config.NoNewPrivileges &&
		(l.config.Capabilities != nil && !utils.StringSliceContains(l.config.Capabilities.Effective, "CAP_SYS_ADMIN")) ||
		(l.config.Config.Capabilities != nil && !utils.StringSliceContains(l.config.Config.Capabilities.Effective, "CAP_SYS_ADMIN")) {

		if l.config.Config.SeccompNotif != nil {
			if err := setupSyscallTraps(l.config, l.pipe); err != nil {
				return newSystemErrorWithCause(err, "loading seccomp notification rules")
			}
			seccompNotifDone = true
		}

		if l.config.Config.Seccomp != nil {
			if _, err := seccomp.InitSeccomp(l.config.Config.Seccomp); err != nil {
				return newSystemErrorWithCause(err, "loading seccomp filtering rules")
			}
			seccompFiltDone = true
		}
	}

	if err := finalizeNamespace(l.config); err != nil {
		return err
	}
	if err := apparmor.ApplyProfile(l.config.AppArmorProfile); err != nil {
		return err
	}

	// Set seccomp as close to execve as possible, so as few syscalls take
	// place afterward (reducing the amount of syscalls that users need to
	// enable in their seccomp profiles).
	if l.config.Config.SeccompNotif != nil && !seccompNotifDone {
		if err := setupSyscallTraps(l.config, l.pipe); err != nil {
			return newSystemErrorWithCause(err, "loading seccomp notification rules")
		}
	}
	if l.config.Config.Seccomp != nil && !seccompFiltDone {
		if _, err := seccomp.InitSeccomp(l.config.Config.Seccomp); err != nil {
			return newSystemErrorWithCause(err, "loading seccomp filtering rules")
		}
	}

	// Close all file descriptors we are not passing to the container. This is
	// necessary because the execve target could use internal sysbox-runc fds as the
	// execve path, potentially giving access to binary files from the host
	// (which can then be opened by container processes, leading to container
	// escapes). Note that because this operation will close any open file
	// descriptors that are referenced by (*os.File) handles from underneath
	// the Go runtime, we must not do any file operations after this point
	// (otherwise the (*os.File) finaliser could close the wrong file). See
	// runc CVE-2024-21626 for more information as to why this protection is
	// necessary.
	if err := utils.UnsafeCloseFrom(l.config.PassedFilesCount + 3); err != nil {
		return err
	}

	return system.Execv(l.config.Args[0], l.config.Args[0:], os.Environ())
}
