package libcontainer

import (
	"fmt"
	"os"
	"runtime"

	"github.com/opencontainers/runc/libsysvisor/shiftfs"
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
	case markShiftfs:
		source := l.mountInfo.Mount.Source
		if err := shiftfs.Mark(source); err != nil {
			return newSystemErrorWithCausef(err, "marking shiftfs on %s", source)
		}
	case bind:
		rootfs := l.mountInfo.Rootfs
		m := &l.mountInfo.Mount
		mountLabel := l.mountInfo.Label

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
