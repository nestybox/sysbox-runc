package libcontainer

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/opencontainers/runc/libsysvisor/shiftfs"
	"github.com/opencontainers/runc/libsysvisor/syscont"
	"github.com/opencontainers/selinux/go-selinux/label"
	"golang.org/x/sys/unix"
)

type linuxRootfsInit struct {
	pipe      *os.File
	mountInfo *mountReqInfo
}

// sysvisor-runc:
// Init performs container rootfs initialization actions from within the container's mount
// namespace only. By virtue of only entering the mount namespace, Init has true
// root-level access to the host and thus can perform operations that the container's init
// process is not allowed to.
func (l *linuxRootfsInit) Init() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	switch l.mountInfo.Op {
	case shiftRootfs:
		source := l.mountInfo.Rootfs
		pid := l.mountInfo.Pid

		if l.mountInfo.Shiftfs {
			if err := shiftfs.Mount(source, pid); err != nil {
				return newSystemErrorWithCausef(err, "mounting shiftfs on rootfs")
			}
		}
	case bind:
		rootfs := l.mountInfo.Rootfs
		m := &l.mountInfo.Mount
		mountLabel := l.mountInfo.Label

		// Only mount shiftfs on bind sources outside of the rootfs (except for sysvisor-fs,
		// since sysvisor-fs emulates file ownership & permissions)
		if l.mountInfo.Shiftfs &&
			!filepath.HasPrefix(m.Source, rootfs) &&
			!filepath.HasPrefix(m.Source, syscont.SysvisorFsDir) {

			// If the bind source is not a directory, mount shiftfs on the directory above
			// the bind source. This is safe because the container does not have access to
			// the full directory, only the bind mounted file.
			fi, err := os.Stat(m.Source)
			if err != nil {
				return newSystemErrorWithCausef(err, "stat %s: %v", m.Source, err)
			}

			var source string
			if fi.IsDir() {
				source = m.Source
			} else {
				source = filepath.Dir(m.Source)
			}

			pid := l.mountInfo.Pid
			if err := shiftfs.Mount(source, pid); err != nil {
				return newSystemErrorWithCausef(err, "mounting shiftfs on bind source %s", source)
			}
		}

		// The call to mountPropagate below requires that the process cwd be the rootfs directory
		if err := unix.Chdir(rootfs); err != nil {
			return newSystemErrorWithCausef(err, "chdir to rootfs %s", rootfs)
		}

		if err := mountPropagate(m, mountLabel); err != nil {
			return newSystemErrorWithCausef(err, "mounting %s to %s", m.Source, m.Destination)
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
	default:
		return newSystemError(fmt.Errorf("invalid init type"))
	}

	if err := writeSync(l.pipe, mountDone); err != nil {
		return err
	}
	l.pipe.Close()
	return nil
}
