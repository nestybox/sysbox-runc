package libcontainer

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"

	"github.com/nestybox/sysbox-runc/libcontainer/mount"
	"github.com/opencontainers/runc/libcontainer/apparmor"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/keys"
	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/selinux/go-selinux"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type linuxStandardInit struct {
	pipe          *os.File
	consoleSocket *os.File
	parentPid     int
	fifoFd        int
	config        *initConfig
}

// sysbox-runc: info passed when the sys container's init process requests its parent runc
// to perform an operation on its behalf.
type opReqType int

const (
	bind = iota
	switchDockerDns
	chown
	mkdir
)

type opReq struct {
	Op      opReqType `json:"type"`
	Rootfs  string    `json:"rootfs"`
	InitPid int       `json:"init_pid"`

	// bind
	Mount configs.Mount `json:"mount"`
	Label string        `json:"label"`

	// switchDockerDns
	OldDns string `json:"olddns"`
	NewDns string `json:"newdns"`

	// chown & mkdir
	Path string      `json:"path"`
	Uid  int         `json:"uid"`
	Gid  int         `json:"gid"`
	Mode os.FileMode `json:"mode"`
}

func (l *linuxStandardInit) getSessionRingParams() (string, uint32, uint32) {
	var newperms uint32

	if l.config.Config.Namespaces.Contains(configs.NEWUSER) {
		// With user ns we need 'other' search permissions.
		newperms = 0x8
	} else {
		// Without user ns we need 'UID' search permissions.
		newperms = 0x80000
	}

	// Create a unique per session container name that we can join in setns;
	// However, other containers can also join it.
	return "_ses." + l.config.ContainerId, 0xffffffff, newperms
}

func (l *linuxStandardInit) Init() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := validateCwd(l.config.Config.Rootfs); err != nil {
		return newSystemErrorWithCause(err, "validating cwd")
	}

	if err := setupNetwork(l.config); err != nil {
		return err
	}
	if err := setupRoute(l.config.Config); err != nil {
		return err
	}

	// initialises the labeling system
	selinux.GetEnabled()
	if err := prepareRootfs(l.pipe, l.config); err != nil {
		return err
	}

	if !l.config.Config.NoNewKeyring {
		if err := selinux.SetKeyLabel(l.config.ProcessLabel); err != nil {
			return err
		}
		defer selinux.SetKeyLabel("")
		ringname, keepperms, newperms := l.getSessionRingParams()

		// Do not inherit the parent's session keyring.
		if sessKeyId, err := keys.JoinSessionKeyring(ringname); err != nil {
			// If keyrings aren't supported then it is likely we are on an
			// older kernel (or inside an LXC container). While we could bail,
			// the security feature we are using here is best-effort (it only
			// really provides marginal protection since VFS credentials are
			// the only significant protection of keyrings).
			//
			// TODO(cyphar): Log this so people know what's going on, once we
			//               have proper logging in 'runc init'.
			if errors.Cause(err) != unix.ENOSYS {
				return errors.Wrap(err, "join session keyring")
			}
		} else {
			// Make session keyring searcheable. If we've gotten this far we
			// bail on any error -- we don't want to have a keyring with bad
			// permissions.
			if err := keys.ModKeyringPerm(sessKeyId, keepperms, newperms); err != nil {
				return errors.Wrap(err, "mod keyring permissions")
			}
		}
	}

	// Set up the console. This has to be done *before* we finalize the rootfs,
	// but *after* we've given the user the chance to set up all of the mounts
	// they wanted.
	if l.config.CreateConsole {
		if err := setupConsole(l.consoleSocket, l.config, true); err != nil {
			return err
		}
		if err := system.Setctty(); err != nil {
			return errors.Wrap(err, "setctty")
		}
	}

	// Finish the rootfs setup.
	if l.config.Config.Namespaces.Contains(configs.NEWNS) {
		if err := finalizeRootfs(l.config.Config); err != nil {
			return err
		}
	}

	if hostname := l.config.Config.Hostname; hostname != "" {
		if err := unix.Sethostname([]byte(hostname)); err != nil {
			return errors.Wrap(err, "sethostname")
		}
	}

	if err := apparmor.ApplyProfile(l.config.AppArmorProfile); err != nil {
		return errors.Wrap(err, "apply apparmor profile")
	}

	// Handle read-only paths
	if len(l.config.Config.ReadonlyPaths) > 0 {
		mounts, err := mount.GetMounts()
		if err != nil {
			return errors.Wrap(err, "getting mounts")
		}

		for _, path := range l.config.Config.ReadonlyPaths {
			if err := readonlyPath(path, mounts); err != nil {
				return errors.Wrapf(err, "readonly path %s", path)
			}
		}
	}

	// Handle masked paths
	for _, path := range l.config.Config.MaskPaths {
		if err := maskPath(path, l.config.Config.MountLabel); err != nil {
			return errors.Wrapf(err, "mask path %s", path)
		}
	}

	// Notify rootfs readiness to parent so that sysbox-fs registration can be
	// completed.
	if err := syncParentRootfsReady(l.pipe); err != nil {
		return errors.Wrap(err, "send immutable list to parent")
	}

	// The instructions that follow and that precede the 'parentReady' signal
	// notification, must all execute after the container has been properly
	// registered with sysbox-fs.
	if l.config.Config.SwitchDockerDns {
		if err := switchDockerDnsIP(l.config.Config, l.pipe); err != nil {
			return errors.Wrap(err, "switching Docker DNS")
		}
	}
	for key, value := range l.config.Config.Sysctl {
		if err := writeSystemProperty(key, value); err != nil {
			return errors.Wrapf(err, "write sysctl key %s", key)
		}
	}

	pdeath, err := system.GetParentDeathSignal()
	if err != nil {
		return errors.Wrap(err, "get pdeath signal")
	}
	if l.config.NoNewPrivileges {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return errors.Wrap(err, "set nonewprivileges")
		}
	}

	// Tell our parent that we're ready to Execv. This must be done before the
	// Seccomp rules have been applied, because we need to be able to read and
	// write to a socket.
	if err := syncParentReady(l.pipe); err != nil {
		return errors.Wrap(err, "sync ready")
	}

	if err := selinux.SetExecLabel(l.config.ProcessLabel); err != nil {
		return errors.Wrap(err, "set process label")
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
				return err
			}
			seccompNotifDone = true
		}

		if l.config.Config.Seccomp != nil {
			if _, err := seccomp.LoadSeccomp(l.config.Config.Seccomp); err != nil {
				return newSystemErrorWithCause(err, "loading seccomp filtering rules")
			}
			seccompFiltDone = true
		}
	}

	// finalizeNamespace drops the caps, sets the correct user and working dir, and marks
	// any leaked file descriptors for closing before executing the command inside the
	// namespace
	if err := finalizeNamespace(l.config); err != nil {
		return err
	}

	// finalizeNamespace can change user/group which clears the parent death
	// signal, so we restore it here.
	if err := pdeath.Restore(); err != nil {
		return errors.Wrap(err, "restore pdeath signal")
	}

	// Compare the parent from the initial start of the init process and make
	// sure that it did not change.  if the parent changes that means it died
	// and we were reparented to something else so we should just kill ourself
	// and not cause problems for someone else.
	if unix.Getppid() != l.parentPid {
		return unix.Kill(unix.Getpid(), unix.SIGKILL)
	}

	// Check for the arg before waiting to make sure it exists and it is
	// returned as a create time error.
	name, err := exec.LookPath(l.config.Args[0])
	if err != nil {
		return err
	}

	// sysbox-runc: setup syscall trapping (must do this before closing the pipe)
	if l.config.Config.SeccompNotif != nil && !seccompNotifDone {
		if err := setupSyscallTraps(l.config, l.pipe); err != nil {
			return err
		}
	}

	// Close the pipe to signal that we have completed our init.
	l.pipe.Close()

	// Wait for the FIFO to be opened on the other side before exec-ing the
	// user process. We open it through /proc/self/fd/$fd, because the fd that
	// was given to us was an O_PATH fd to the fifo itself. Linux allows us to
	// re-open an O_PATH fd through /proc.
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(l.fifoFd), unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return newSystemErrorWithCause(err, "open exec fifo")
	}
	if _, err := unix.Write(fd, []byte("0")); err != nil {
		return newSystemErrorWithCause(err, "write 0 exec fifo")
	}

	// Close the O_PATH fifofd fd before exec because the kernel resets
	// dumpable in the wrong order. This has been fixed in newer kernels, but
	// we keep this to ensure CVE-2016-9962 doesn't re-emerge on older kernels.
	// N.B. the core issue itself (passing dirfds to the host filesystem) has
	// since been resolved.
	// https://github.com/torvalds/linux/blob/v4.9/fs/exec.c#L1290-L1318
	unix.Close(l.fifoFd)

	// Load the seccomp syscall whitelist as close to execve as possible, so as few
	// syscalls take place afterward (reducing the amount of syscalls that users need to
	// enable in their seccomp profiles).
	if l.config.Config.Seccomp != nil && !seccompFiltDone {
		if _, err := seccomp.LoadSeccomp(l.config.Config.Seccomp); err != nil {
			return newSystemErrorWithCause(err, "loading seccomp filtering rules")
		}
	}

	s := l.config.SpecState
	s.Pid = unix.Getpid()
	s.Status = specs.StateCreated
	if err := l.config.Config.Hooks[configs.StartContainer].RunHooks(s); err != nil {
		return err
	}

	if err := unix.Exec(name, l.config.Args[0:], os.Environ()); err != nil {
		return newSystemErrorWithCausef(err, "exec user process: name = %v, args = %v, environ = %v", name, l.config.Args[0:], os.Environ())
	}
	return nil
}
