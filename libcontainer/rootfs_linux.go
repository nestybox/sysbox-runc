//go:build linux
// +build linux

package libcontainer

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/nestybox/sysbox-runc/libcontainer/mount"

	"github.com/moby/sys/mountinfo"

	"github.com/mrunalp/fileutils"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/devices"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/runc/libcontainer/utils"
	libcontainerUtils "github.com/opencontainers/runc/libcontainer/utils"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/selinux/go-selinux/label"
	"golang.org/x/sys/unix"
)

const defaultMountFlags = unix.MS_NOEXEC | unix.MS_NOSUID | unix.MS_NODEV

// needsSetupDev returns true if /dev needs to be set up.
func needsSetupDev(config *configs.Config) bool {
	for _, m := range config.Mounts {
		if m.Device == "bind" && libcontainerUtils.CleanPath(m.Destination) == "/dev" {
			return false
		}
	}
	return true
}

// prepareRootfs sets up the devices, mount points, and filesystems for use inside a new
// mount namespace. It must be called from the container's rootfs. It doesn't set anything
// as ro. You must call finalizeRootfs after this function to finish setting up the
// rootfs.
func prepareRootfs(pipe io.ReadWriter, iConfig *initConfig) (err error) {
	config := iConfig.Config

	if err := validateCwd(config.Rootfs); err != nil {
		return newSystemErrorWithCause(err, "validating cwd")
	}

	if err := effectRootfsMount(); err != nil {
		return newSystemErrorWithCause(err, "effecting rootfs mount")
	}

	if err := doMounts(config, pipe); err != nil {
		return newSystemErrorWithCause(err, "setting up rootfs mounts")
	}

	setupDev := needsSetupDev(config)
	if setupDev {
		if err := createDevices(config, pipe); err != nil {
			return newSystemErrorWithCause(err, "creating device nodes")
		}
		if err := setupPtmx(config); err != nil {
			return newSystemErrorWithCause(err, "setting up ptmx")
		}
		if err := setupDevSymlinks(config.Rootfs); err != nil {
			return newSystemErrorWithCause(err, "setting up /dev symlinks")
		}
	}

	// Signal the parent to run the pre-start hooks.
	// The hooks are run after the mounts are setup, but before we switch to the new
	// root, so that the old root is still available in the hooks for any mount
	// manipulations.
	// Note that iConfig.Cwd is not guaranteed to exist here.
	if err := syncParentHooks(pipe); err != nil {
		return err
	}

	// The reason these operations are done here rather than in finalizeRootfs
	// is because the console-handling code gets quite sticky if we have to set
	// up the console before doing the pivot_root(2). This is because the
	// Console API has to also work with the ExecIn case, which means that the
	// API must be able to deal with being inside as well as outside the
	// container. It's just cleaner to do this here (at the expense of the
	// operation not being perfectly split).

	s := iConfig.SpecState
	s.Pid = unix.Getpid()
	s.Status = specs.StateCreating
	if err := iConfig.Config.Hooks[configs.CreateContainer].RunHooks(s); err != nil {
		return err
	}

	if config.NoPivotRoot {
		err = msMoveRoot(config.Rootfs)
	} else if config.Namespaces.Contains(configs.NEWNS) {
		err = pivotRoot(config.Rootfs)
	} else {
		err = chroot()
	}
	if err != nil {
		return newSystemErrorWithCause(err, "jailing process inside rootfs")
	}

	// Add pending fsState to container's rootfs.
	if err := addFsState(config); err != nil {
		return newSystemErrorWithCause(err, "adding rootfs state")
	}

	if setupDev {
		if err := reOpenDevNull(); err != nil {
			return newSystemErrorWithCause(err, "reopening /dev/null inside container")
		}
	}

	if cwd := iConfig.Cwd; cwd != "" {
		// Note that spec.Process.Cwd can contain unclean value like  "../../../../foo/bar...".
		// However, we are safe to call MkDirAll directly because we are in the jail here.
		if err := os.MkdirAll(cwd, 0755); err != nil {
			return err
		}
	}

	return nil
}

// finalizeRootfs sets anything to ro if necessary.
func finalizeRootfs(config *configs.Config) (err error) {
	// remount dev as ro if specified
	for _, m := range config.Mounts {
		if libcontainerUtils.CleanPath(m.Destination) == "/dev" {
			if m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {
				if err := remountReadonly(m); err != nil {
					return newSystemErrorWithCausef(err, "remounting %q as readonly", m.Destination)
				}
			}
			break
		}
	}

	// set rootfs ( / ) as readonly
	if config.Readonlyfs {
		if err := setReadonly(); err != nil {
			return newSystemErrorWithCause(err, "setting rootfs as readonly")
		}
	}

	if config.Umask != nil {
		unix.Umask(int(*config.Umask))
	} else {
		unix.Umask(0022)
	}
	return nil
}

// /tmp has to be mounted as private to allow MS_MOVE to work in all situations
func prepareTmp(topTmpDir string) (string, error) {
	tmpdir, err := ioutil.TempDir(topTmpDir, "runctop")
	if err != nil {
		return "", err
	}
	if err := unix.Mount(tmpdir, tmpdir, "bind", unix.MS_BIND, ""); err != nil {
		return "", err
	}
	if err := unix.Mount("", tmpdir, "", uintptr(unix.MS_PRIVATE), ""); err != nil {
		return "", err
	}
	return tmpdir, nil
}

func cleanupTmp(tmpdir string) error {
	unix.Unmount(tmpdir, 0)
	return os.RemoveAll(tmpdir)
}

func mountCmd(cmd configs.Command) error {
	command := exec.Command(cmd.Path, cmd.Args[:]...)
	command.Env = cmd.Env
	command.Dir = cmd.Dir
	if out, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%#v failed: %s: %v", cmd, string(out), err)
	}
	return nil
}

func prepareBindDest(m *configs.Mount, absDestPath bool, config *configs.Config, pipe io.ReadWriter) (err error) {
	var base, dest string

	// ensure that the destination of the bind mount is resolved of symlinks at mount time because
	// any previous mounts can invalidate the next mount's destination.
	// this can happen when a user specifies mounts within other mounts to cause breakouts or other
	// evil stuff to try to escape the container's rootfs.

	if absDestPath {
		base = config.Rootfs
	} else {
		base = "."
	}

	if dest, err = securejoin.SecureJoin(base, m.Destination); err != nil {
		return err
	}

	// update the mount with the correct dest after symlinks are resolved.
	m.Destination = dest
	if err = createIfNotExists(dest, m.BindSrcInfo.IsDir, config, pipe); err != nil {
		return err
	}

	return nil
}

func mountCgroupV1(m *configs.Mount, enableCgroupns bool, config *configs.Config, pipe io.ReadWriter) error {
	binds, err := getCgroupMounts(m)
	if err != nil {
		return err
	}
	var merged []string
	for _, b := range binds {
		ss := filepath.Base(b.Destination)
		if strings.Contains(ss, ",") {
			merged = append(merged, ss)
		}
	}
	tmpfs := &configs.Mount{
		Source:           "tmpfs",
		Device:           "tmpfs",
		Destination:      m.Destination,
		Flags:            defaultMountFlags,
		Data:             "mode=755",
		PropagationFlags: m.PropagationFlags,
	}

	if err := mountToRootfs(tmpfs, config, enableCgroupns, pipe); err != nil {
		return err
	}
	for _, b := range binds {
		if enableCgroupns {
			// sysbox-runc: use relative path (as otherwise we may not have permission to mkdir)
			subsystemPath := b.Destination
			if err := mkdirall(subsystemPath, 0755, config, pipe); err != nil {
				return err
			}
			flags := defaultMountFlags
			if m.Flags&unix.MS_RDONLY != 0 {
				flags = flags | unix.MS_RDONLY
			}
			cgroupmount := &configs.Mount{
				Source:      "cgroup",
				Device:      "cgroup", // this is actually fstype
				Destination: subsystemPath,
				Flags:       flags,
				Data:        filepath.Base(subsystemPath),
			}
			if err := mountNewCgroup(cgroupmount); err != nil {
				return err
			}
		} else {
			if err := mountToRootfs(b, config, enableCgroupns, pipe); err != nil {
				return err
			}
		}
	}
	for _, mc := range merged {
		for _, ss := range strings.Split(mc, ",") {
			// symlink(2) is very dumb, it will just shove the path into
			// the link and doesn't do any checks or relative path
			// conversion. Also, don't error out if the cgroup already exists.
			if err := os.Symlink(mc, filepath.Join(m.Destination, ss)); err != nil && !os.IsExist(err) {
				return err
			}
		}
	}
	return nil
}

func mountCgroupV2(m *configs.Mount, enableCgroupns bool, config *configs.Config, pipe io.ReadWriter) error {
	cgroupPath, err := securejoin.SecureJoin(".", m.Destination)
	if err != nil {
		return err
	}
	if err := mkdirall(cgroupPath, 0755, config, pipe); err != nil {
		return err
	}
	if err := unix.Mount(m.Source, cgroupPath, "cgroup2", uintptr(m.Flags), m.Data); err != nil {
		// when we are in UserNS but CgroupNS is not unshared, we cannot mount cgroup2 (#2158)
		if err == unix.EPERM || err == unix.EBUSY {
			return unix.Mount("/sys/fs/cgroup", cgroupPath, "", uintptr(m.Flags)|unix.MS_BIND, "")
		}
		return err
	}
	return nil
}

// mkdirall calls into os.Mkdirall(), but precedes the call with an open of the current
// working directory (cwd). This avoids permission-denied problems on the Mkdirall call
// when shiftfs is mounted on the cwd. The exact cause of the permission problem is not
// clear and needs further investigation.
func mkdirall(path string, mode os.FileMode, config *configs.Config, pipe io.ReadWriter) error {

	fd, err := syscall.Open(".", unix.O_PATH|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("failed to open current dir.")
	}

	if err := syscall.Fchdir(fd); err != nil {
		return fmt.Errorf("fchdir %s failed: %v", path, err)
	}

	if err := os.MkdirAll(path, mode); err != nil {

		// In some cases the container's init process process won't have
		// permission to perform the mkdir (e.g., if the parent directory in the
		// image is owned by root:root on the host). In this case, we ask the
		// parent sysbox-runc process to do this for us.

		req := opReq{
			Op:     mkdir,
			Rootfs: config.Rootfs,
			Path:   path,
			Mode:   mode,
			Uid:    config.UidMappings[0].HostID,
			Gid:    config.GidMappings[0].HostID,
		}

		if err := syncParentDoOp([]opReq{req}, pipe); err != nil {
			return fmt.Errorf("mkdirall %s with mode %o failed: %v", path, mode, err)
		}
	}

	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("failed to close fd %d", fd)
	}

	return nil
}

func mountToRootfs(m *configs.Mount, config *configs.Config, enableCgroupns bool, pipe io.ReadWriter) error {
	var (
		mountLabel = config.MountLabel
		dest       = m.Destination
	)

	// This function assumes cwd is the container's rootfs
	dest = filepath.Join(".", dest)
	m.Destination = dest

	switch m.Device {
	case "proc", "sysfs":
		// If the destination already exists and is not a directory, we bail
		// out This is to avoid mounting through a symlink or similar -- which
		// has been a "fun" attack scenario in the past.
		// TODO: This won't be necessary once we switch to libpathrs and we can
		//       stop all of these symlink-exchange attacks.
		if fi, err := os.Lstat(dest); err != nil {
			if !os.IsNotExist(err) {
				return err
			}
		} else if fi.Mode()&os.ModeDir == 0 {
			return fmt.Errorf("filesystem %q must be mounted on ordinary directory", m.Device)
		}
		if err := mkdirall(dest, 0755, config, pipe); err != nil {
			return fmt.Errorf("failed to created dir for %s mount: %v", m.Device, err)
		}
		// Selinux kernels do not support labeling of /proc or /sys
		return mountPropagate(m, "")
	case "mqueue":
		if err := mkdirall(dest, 0755, config, pipe); err != nil {
			return err
		}
		if err := mountPropagate(m, ""); err != nil {
			return err
		}
		return label.SetFileLabel(dest, mountLabel)
	case "tmpfs":
		copyUp := m.Extensions&configs.EXT_COPYUP == configs.EXT_COPYUP
		tmpDir := ""
		// dest might be an absolute symlink, so it needs
		// to be resolved under rootfs.
		dest, err := securejoin.SecureJoin(".", m.Destination)
		if err != nil {
			return err
		}
		m.Destination = dest
		stat, err := os.Stat(dest)
		if err != nil {
			if err := mkdirall(dest, 0755, config, pipe); err != nil {
				return err
			}
		}
		if copyUp {
			tmpdir, err := prepareTmp("/tmp")
			if err != nil {
				return newSystemErrorWithCause(err, "tmpcopyup: failed to setup tmpdir")
			}
			defer cleanupTmp(tmpdir)
			tmpDir, err = ioutil.TempDir(tmpdir, "runctmpdir")
			if err != nil {
				return newSystemErrorWithCause(err, "tmpcopyup: failed to create tmpdir")
			}
			defer os.RemoveAll(tmpDir)
			m.Destination = tmpDir
		}
		if err := mountPropagate(m, mountLabel); err != nil {
			return err
		}
		if copyUp {
			if err := fileutils.CopyDirectory(dest, tmpDir); err != nil {
				errMsg := fmt.Errorf("tmpcopyup: failed to copy %s to %s: %v", dest, tmpDir, err)
				if err1 := unix.Unmount(tmpDir, unix.MNT_DETACH); err1 != nil {
					return newSystemErrorWithCausef(err1, "tmpcopyup: %v: failed to unmount", errMsg)
				}
				return errMsg
			}
			if err := unix.Mount(tmpDir, dest, "", unix.MS_MOVE, ""); err != nil {
				errMsg := fmt.Errorf("tmpcopyup: failed to move mount %s to %s: %v", tmpDir, dest, err)
				if err1 := unix.Unmount(tmpDir, unix.MNT_DETACH); err1 != nil {
					return newSystemErrorWithCausef(err1, "tmpcopyup: %v: failed to unmount", errMsg)
				}
				return errMsg
			}
		}
		if stat != nil {
			if err = os.Chmod(dest, stat.Mode()); err != nil {
				return err
			}
		}
		// Initially mounted rw in mountPropagate, remount to ro if flag set.
		if m.Flags&unix.MS_RDONLY != 0 {
			if err := remount(m); err != nil {
				return err
			}
		}
		return nil
	case "cgroup":
		if cgroups.IsCgroup2UnifiedMode() {
			return mountCgroupV2(m, enableCgroupns, config, pipe)
		}
		return mountCgroupV1(m, enableCgroupns, config, pipe)
	default:
		// ensure that the destination of the mount is resolved of symlinks at mount time because
		// any previous mounts can invalidate the next mount's destination.
		// this can happen when a user specifies mounts within other mounts to cause breakouts or other
		// evil stuff to try to escape the container's rootfs.
		if err := mkdirall(dest, 0755, config, pipe); err != nil {
			return err
		}
		return mountPropagate(m, mountLabel)
	}
}

func doBindMounts(config *configs.Config, pipe io.ReadWriter) error {

	// sysbox-runc: the sys container's init process is in a dedicated
	// user-ns, so it may not have search permission to the bind mount
	// sources (and thus can't perform the bind mount itself). As a
	// result, we perform the bind mounts by asking the parent
	// sysbox-runc to spawn a helper child process which enters the
	// container's mount namespace (only) and performs the mounts. That
	// helper process has true root credentials (because it's in the
	// initial user-ns rather than the sys container's user-ns) yet it
	// can perform mounts inside the container.
	//
	// Also, to avoid sending too many requests to our parent
	// sysbox-runc, we group bind mounts and send a bulk request, with
	// one exception: when a bind mount depends on a prior one, we must
	// ask the parent sysbox-runc to perform the prior ones before we
	// can prepare the bind destination and perform the current one.

	mntReqs := []opReq{}

	for _, m := range config.Mounts {

		if m.Device != "bind" {
			continue
		}

		// Determine if the current mount is dependent on a prior one.
		mntDependsOnPrior := false
		for _, mr := range mntReqs {

			// Mount destinations in mntReqs are relative to the rootfs
			// (see prepareBindDest()); thus we need to prepend "/" for a
			// proper comparison.
			if strings.HasPrefix(m.Destination, filepath.Join("/", mr.Mount.Destination)) {
				mntDependsOnPrior = true
			}
		}

		// If the current mount depends on a prior one, ask our parent
		// runc to actually do the prior mount(s).
		if mntDependsOnPrior {
			if len(mntReqs) > 0 {
				if err := syncParentDoOp(mntReqs, pipe); err != nil {
					return newSystemErrorWithCause(err, "syncing with parent runc to perform bind mounts")
				}
				mntReqs = mntReqs[:0]
			}
		}

		if err := prepareBindDest(m, false, config, pipe); err != nil {
			return err
		}

		req := opReq{
			Op:     bind,
			Mount:  *m,
			Label:  config.MountLabel,
			Rootfs: config.Rootfs,
		}

		mntReqs = append(mntReqs, req)
	}

	if len(mntReqs) > 0 {
		if err := syncParentDoOp(mntReqs, pipe); err != nil {
			return newSystemErrorWithCause(err, "syncing with parent runc to perform bind mounts")
		}
	}

	return nil
}

func chownMounts(config *configs.Config, pipe io.ReadWriter, chownList []string) error {
	chownReqs := []opReq{}

	if config.UidMappings != nil && config.GidMappings != nil {
		for _, path := range chownList {
			req := opReq{
				Op:     chown,
				Rootfs: config.Rootfs,
				Path:   path,
				Uid:    config.UidMappings[0].HostID,
				Gid:    config.GidMappings[0].HostID,
			}
			chownReqs = append(chownReqs, req)
		}
	}

	if len(chownReqs) > 0 {
		if err := syncParentDoOp(chownReqs, pipe); err != nil {
			return newSystemErrorWithCause(err, "syncing with parent runc to chown mounts")
		}
	}

	return nil
}

func getCgroupMounts(m *configs.Mount) ([]*configs.Mount, error) {
	mounts, err := cgroups.GetCgroupMounts(false)
	if err != nil {
		return nil, err
	}

	cgroupPaths, err := cgroups.ParseCgroupFile("/proc/self/cgroup")
	if err != nil {
		return nil, err
	}

	var binds []*configs.Mount

	for _, mm := range mounts {
		dir, err := mm.GetOwnCgroup(cgroupPaths)
		if err != nil {
			return nil, err
		}
		relDir, err := filepath.Rel(mm.Root, dir)
		if err != nil {
			return nil, err
		}
		binds = append(binds, &configs.Mount{
			Device:           "bind",
			Source:           filepath.Join(mm.Mountpoint, relDir),
			Destination:      filepath.Join(m.Destination, filepath.Base(mm.Mountpoint)),
			Flags:            unix.MS_BIND | unix.MS_REC | m.Flags,
			PropagationFlags: m.PropagationFlags,
		})
	}

	return binds, nil
}

func setupDevSymlinks(rootfs string) error {
	var links = [][2]string{
		{"/proc/self/fd", "/dev/fd"},
		{"/proc/self/fd/0", "/dev/stdin"},
		{"/proc/self/fd/1", "/dev/stdout"},
		{"/proc/self/fd/2", "/dev/stderr"},
	}
	// kcore support can be toggled with CONFIG_PROC_KCORE; only create a symlink
	// in /dev if it exists in /proc.
	if _, err := os.Stat("/proc/kcore"); err == nil {
		links = append(links, [2]string{"/proc/kcore", "/dev/core"})
	}
	for _, link := range links {
		var (
			src = link[0]
			dst = filepath.Join(".", link[1])
		)
		if err := os.Symlink(src, dst); err != nil && !os.IsExist(err) {
			return fmt.Errorf("symlink %s %s %s", src, dst, err)
		}
	}
	return nil
}

// If stdin, stdout, and/or stderr are pointing to `/dev/null` in the parent's rootfs
// this method will make them point to `/dev/null` in this container's rootfs.  This
// needs to be called after we chroot/pivot into the container's rootfs so that any
// symlinks are resolved locally.
func reOpenDevNull() error {
	var stat, devNullStat unix.Stat_t
	file, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("Failed to open /dev/null - %s", err)
	}
	defer file.Close()
	if err := unix.Fstat(int(file.Fd()), &devNullStat); err != nil {
		return err
	}
	for fd := 0; fd < 3; fd++ {
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		if stat.Rdev == devNullStat.Rdev {
			// Close and re-open the fd.
			if err := unix.Dup3(int(file.Fd()), fd, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

// Create the device nodes in the container.
func createDevices(config *configs.Config, pipe io.ReadWriter) error {
	useBindMount := system.RunningInUserNS() || config.Namespaces.Contains(configs.NEWUSER)
	oldMask := unix.Umask(0000)
	for _, node := range config.Devices {

		// The /dev/ptmx device is setup by setupPtmx()
		if utils.CleanPath(node.Path) == "/dev/ptmx" {
			continue
		}

		// containers running in a user namespace are not allowed to mknod
		// devices so we can just bind mount it from the host.
		if err := createDeviceNode(node, useBindMount, config, pipe); err != nil {
			unix.Umask(oldMask)
			return err
		}
	}
	unix.Umask(oldMask)
	return nil
}

func bindMountDeviceNode(dest string, node *devices.Device) error {
	f, err := os.Create(dest)
	if err != nil && !os.IsExist(err) {
		return err
	}
	if f != nil {
		f.Close()
	}

	if err := unix.Mount(node.Path, dest, "bind", unix.MS_BIND, ""); err != nil {
		return err
	}

	return nil
}

// Creates the device node in the rootfs of the container.
func createDeviceNode(node *devices.Device, bind bool, config *configs.Config, pipe io.ReadWriter) error {
	if node.Path == "" {
		// The node only exists for cgroup reasons, ignore it here.
		return nil
	}
	dest := filepath.Join(".", node.Path)

	if err := mkdirall(filepath.Dir(dest), 0755, config, pipe); err != nil {
		return err
	}
	if bind {
		return bindMountDeviceNode(dest, node)
	}
	if err := mknodDevice(dest, node); err != nil {
		if os.IsExist(err) {
			return nil
		} else if os.IsPermission(err) {
			return bindMountDeviceNode(dest, node)
		}
		return err
	}
	return nil
}

func mknodDevice(dest string, node *devices.Device) error {
	fileMode := node.FileMode
	switch node.Type {
	case devices.BlockDevice:
		fileMode |= unix.S_IFBLK
	case devices.CharDevice:
		fileMode |= unix.S_IFCHR
	case devices.FifoDevice:
		fileMode |= unix.S_IFIFO
	default:
		return fmt.Errorf("%c is not a valid device type for device %s", node.Type, node.Path)
	}
	dev, err := node.Mkdev()
	if err != nil {
		return err
	}
	if err := unix.Mknod(dest, uint32(fileMode), int(dev)); err != nil {
		return err
	}
	return unix.Chown(dest, int(node.Uid), int(node.Gid))
}

// Get the parent mount point of directory passed in as argument. Also return
// optional fields.
func getParentMount(rootfs string) (string, string, error) {
	mi, err := mountinfo.GetMounts(mountinfo.ParentsFilter(rootfs))
	if err != nil {
		return "", "", err
	}
	if len(mi) < 1 {
		return "", "", fmt.Errorf("could not find parent mount of %s", rootfs)
	}

	// find the longest mount point
	var idx, maxlen int
	for i := range mi {
		if len(mi[i].Mountpoint) > maxlen {
			maxlen = len(mi[i].Mountpoint)
			idx = i
		}
	}
	return mi[idx].Mountpoint, mi[idx].Optional, nil
}

// Indicates if our parent mount has shared propagation
func rootfsParentMountIsShared(rootfs string) (bool, string, error) {
	sharedMount := false

	parentMount, optionalOpts, err := getParentMount(rootfs)
	if err != nil {
		return false, "", err
	}

	optsSplit := strings.Split(optionalOpts, " ")
	for _, opt := range optsSplit {
		if strings.HasPrefix(opt, "shared:") {
			sharedMount = true
			break
		}
	}

	return sharedMount, parentMount, nil
}

func setReadonly() error {
	flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY)

	err := unix.Mount("", "/", "", flags, "")
	if err == nil {
		return nil
	}
	var s unix.Statfs_t
	if err := unix.Statfs("/", &s); err != nil {
		return &os.PathError{Op: "statfs", Path: "/", Err: err}
	}
	flags |= uintptr(s.Flags)
	return unix.Mount("", "/", "", flags, "")

}

func setupPtmx(config *configs.Config) error {
	ptmx := "dev/ptmx"
	if err := os.Remove(ptmx); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink("pts/ptmx", ptmx); err != nil {
		return fmt.Errorf("symlink dev ptmx %s", err)
	}
	return nil
}

// pivotRoot will call pivot_root such that rootfs becomes the new root
// filesystem, and everything else is cleaned up.
func pivotRoot(rootfs string) error {
	// While the documentation may claim otherwise, pivot_root(".", ".") is
	// actually valid. What this results in is / being the new root but
	// /proc/self/cwd being the old root. Since we can play around with the cwd
	// with pivot_root this allows us to pivot without creating directories in
	// the rootfs. Shout-outs to the LXC developers for giving us this idea.

	oldroot, err := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(oldroot)

	newroot, err := unix.Open(".", unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(newroot)

	// Change to the new root so that the pivot_root actually acts on it.
	if err := unix.Fchdir(newroot); err != nil {
		return err
	}

	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root %s", err)
	}

	// Currently our "." is oldroot (according to the current kernel code).
	// However, purely for safety, we will fchdir(oldroot) since there isn't
	// really any guarantee from the kernel what /proc/self/cwd will be after a
	// pivot_root(2).

	if err := unix.Fchdir(oldroot); err != nil {
		return err
	}

	// Make oldroot rslave to make sure our unmounts don't propagate to the
	// host (and thus bork the machine). We don't use rprivate because this is
	// known to cause issues due to races where we still have a reference to a
	// mount while a process in the host namespace are trying to operate on
	// something they think has no mounts (devicemapper in particular).
	if err := unix.Mount("", ".", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		return err
	}

	// Perform the unmount. MNT_DETACH allows us to unmount /proc/self/cwd.
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return err
	}

	// Switch back to our shiny new root.
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("chdir / %s", err)
	}
	return nil
}

func msMoveRoot(rootfs string) error {
	// Before we move the root and chroot we have to mask all "full" sysfs and
	// procfs mounts which exist on the host. This is because while the kernel
	// has protections against mounting procfs if it has masks, when using
	// chroot(2) the *host* procfs mount is still reachable in the mount
	// namespace and the kernel permits procfs mounts inside --no-pivot
	// containers.
	//
	// Users shouldn't be using --no-pivot except in exceptional circumstances,
	// but to avoid such a trivial security flaw we apply a best-effort
	// protection here. The kernel only allows a mount of a pseudo-filesystem
	// like procfs or sysfs if there is a *full* mount (the root of the
	// filesystem is mounted) without any other locked mount points covering a
	// subtree of the mount.
	//
	// So we try to unmount (or mount tmpfs on top of) any mountpoint which is
	// a full mount of either sysfs or procfs (since those are the most
	// concerning filesystems to us).
	mountinfos, err := mountinfo.GetMounts(func(info *mountinfo.Info) (skip, stop bool) {
		// Collect every sysfs and procfs filesystem, except for those which
		// are non-full mounts or are inside the rootfs of the container.
		if info.Root != "/" ||
			(info.FSType != "proc" && info.FSType != "sysfs") ||
			strings.HasPrefix(info.Mountpoint, rootfs) {
			skip = true
		}
		return
	})
	if err != nil {
		return err
	}
	for _, info := range mountinfos {
		p := info.Mountpoint
		// Be sure umount events are not propagated to the host.
		if err := unix.Mount("", p, "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
			if err == unix.ENOENT {
				// If the mountpoint doesn't exist that means that we've
				// already blasted away some parent directory of the mountpoint
				// and so we don't care about this error.
				continue
			}
			return err
		}
		if err := unix.Unmount(p, unix.MNT_DETACH); err != nil {
			if err != unix.EINVAL && err != unix.EPERM {
				return err
			} else {
				// If we have not privileges for umounting (e.g. rootless), then
				// cover the path.
				if err := unix.Mount("tmpfs", p, "tmpfs", 0, ""); err != nil {
					return err
				}
			}
		}
	}

	// Move the rootfs on top of "/" in our mount namespace.
	if err := unix.Mount(rootfs, "/", "", unix.MS_MOVE, ""); err != nil {
		return err
	}
	return chroot()
}

func chroot() error {
	if err := unix.Chroot("."); err != nil {
		return err
	}
	return unix.Chdir("/")
}

// createIfNotExists creates a file or a directory only if it does not already exist.
func createIfNotExists(path string, isDir bool, config *configs.Config, pipe io.ReadWriter) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			if isDir {
				return mkdirall(path, 0755, config, pipe)
			}
			if err := mkdirall(filepath.Dir(path), 0755, config, pipe); err != nil {
				return err
			}
			f, err := os.OpenFile(path, os.O_CREATE, 0755)
			if err != nil {
				return err
			}
			f.Close()
		}
	}
	return nil
}

// readonlyPath will make a path read only.
func readonlyPath(path string, mounts []*mount.Info) error {
	isMountpoint := mount.FindMount(path, mounts)

	if !isMountpoint {
		if err := unix.Mount(path, path, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
	}

	m := &configs.Mount{
		Destination: path,
		Flags:       unix.MS_BIND | unix.MS_RDONLY | unix.MS_REC,
	}

	return remount(m)
}

// remountReadonly will remount an existing mount point and ensure that it is read-only.
func remountReadonly(m *configs.Mount) error {
	var (
		dest  = m.Destination
		flags = m.Flags
	)
	for i := 0; i < 5; i++ {
		// There is a special case in the kernel for
		// MS_REMOUNT | MS_BIND, which allows us to change only the
		// flags even as an unprivileged user (i.e. user namespace)
		// assuming we don't drop any security related flags (nodev,
		// nosuid, etc.). So, let's use that case so that we can do
		// this re-mount without failing in a userns.
		flags |= unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY
		if err := unix.Mount("", dest, "", uintptr(flags), ""); err != nil {
			switch err {
			case unix.EBUSY:
				time.Sleep(100 * time.Millisecond)
				continue
			default:
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unable to mount %s as readonly max retries reached", dest)
}

// remountReadwrite will remount an existing mount point with read-write permissions.
func remountReadwrite(m *configs.Mount) error {
	var (
		dest  = m.Destination
		flags = m.Flags
	)

	for i := 0; i < 5; i++ {
		// There is a special case in the kernel for
		// MS_REMOUNT | MS_BIND, which allows us to change only the
		// flags even as an unprivileged user (i.e. user namespace)
		// assuming we don't drop any security related flags (nodev,
		// nosuid, etc.). So, let's use that case so that we can do
		// this re-mount without failing in a userns.
		flags = (flags &^ unix.MS_RDONLY) | unix.MS_REMOUNT | unix.MS_BIND

		if err := unix.Mount("", dest, "", uintptr(flags), ""); err != nil {
			switch err {
			case unix.EBUSY:
				time.Sleep(100 * time.Millisecond)
				continue
			default:
				return err
			}
		}
		return nil
	}

	return fmt.Errorf("unable to mount %s as readwrite max retries reached", dest)
}

// maskPath masks the top of the specified path inside a container to avoid
// security issues from processes reading information from non-namespace aware
// mounts ( proc/kcore ).
// For files, maskPath bind mounts /dev/null over the top of the specified path.
// For directories, maskPath mounts read-only tmpfs over the top of the specified path.
func maskPath(path string, mountLabel string) error {
	if err := unix.Mount("/dev/null", path, "", unix.MS_BIND, ""); err != nil && !os.IsNotExist(err) {
		if err == unix.ENOTDIR {
			return unix.Mount("tmpfs", path, "tmpfs", unix.MS_RDONLY, label.FormatMountLabel("", mountLabel))
		}
		return err
	}
	return nil
}

// writeSystemProperty writes the value to a path under /proc/sys as determined from the key.
// For e.g. net.ipv4.ip_forward translated to /proc/sys/net/ipv4/ip_forward.
func writeSystemProperty(key, value string) error {
	keyPath := strings.Replace(key, ".", "/", -1)
	return ioutil.WriteFile(path.Join("/proc/sys", keyPath), []byte(value), 0644)
}

func remount(m *configs.Mount) error {
	flags := uintptr(m.Flags | unix.MS_REMOUNT)

	// Per mount(2): remounting must keep original mount flags, except the flags being changed
	var s unix.Statfs_t
	if err := unix.Statfs(m.Destination, &s); err != nil {
		return &os.PathError{Op: "statfs", Path: m.Destination, Err: err}
	}
	flags |= uintptr(s.Flags)

	if err := unix.Mount("", m.Destination, "", flags, ""); err != nil {
		return fmt.Errorf("failed to remount %s with flags %#x", m.Destination, int(flags))
	}

	return nil
}

// Do the mount operation followed by additional mounts required to take care
// of propagation flags.
func mountPropagate(m *configs.Mount, mountLabel string) error {
	var (
		dest  = m.Destination
		data  = label.FormatMountLabel(m.Data, mountLabel)
		flags = m.Flags
	)
	if dest == "dev" {
		flags &= ^unix.MS_RDONLY
	}

	// Mount it rw to allow chmod operation. A remount will be performed
	// later to make it ro if set.
	if m.Device == "tmpfs" {
		flags &= ^unix.MS_RDONLY
	}

	if err := unix.Mount(m.Source, dest, m.Device, uintptr(flags), data); err != nil {
		return err
	}

	for _, pflag := range m.PropagationFlags {
		if err := unix.Mount("", dest, "", uintptr(pflag), ""); err != nil {
			return err
		}
	}

	return nil
}

func mountNewCgroup(m *configs.Mount) error {
	var (
		data   = m.Data
		source = m.Source
	)
	if data == "systemd" {
		data = cgroups.CgroupNamePrefix + data
		source = "systemd"
	}
	if err := unix.Mount(source, m.Destination, m.Device, uintptr(m.Flags), data); err != nil {
		return err
	}
	return nil
}

// sysbox-runc: doMounts sets up all of the container's mounts as specified in the given config.
func doMounts(config *configs.Config, pipe io.ReadWriter) error {

	chownList := []string{}

	// Do non-bind mounts
	for _, m := range config.Mounts {
		if m.Device != "bind" {
			if err := mountToRootfs(m, config, true, pipe); err != nil {
				return newSystemErrorWithCausef(err, "mounting %q to rootfs %q at %q", m.Source, config.Rootfs, m.Destination)
			}

			// Change ownership of the container's /proc to match the container's
			// root user. This prevents /proc showing up as nobody:nogroup
			// yet does not give any extra permissions to the container. It not only
			// looks better, but helps prevents problems such as
			// https://github.com/nestybox/sysbox/issues/130.
			//
			// Note: ideally we would do the same for "/sys", but we can't because
			// changing ownership of any sysfs mountpoint causes the ownership
			// change to propagate to all other sysfs mountpoints in the system.

			if m.Device == "proc" {
				chownList = append(chownList, "proc")
			}
		}
	}

	if err := doBindMounts(config, pipe); err != nil {
		return err
	}

	if err := chownMounts(config, pipe, chownList); err != nil {
		return err
	}

	return nil
}

// sysbox-runc: validateCwd verifies that the current working directory is the container's
// rootfs
func validateCwd(rootfs string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return newSystemErrorWithCause(err, "getting cwd")
	}
	if cwd != rootfs {
		return newSystemErrorWithCausef(err, "cwd %s is not container's rootfs %s", cwd, rootfs)
	}
	return nil
}

// sysbox-runc: effectRootfsMount ensure the calling process sees the effects of a previous rootfs
// mount. It does this by reopening the rootfs directory.
func effectRootfsMount() error {

	// @ctalledo: the method for reopening the rootfs directory is pretty lame,
	// but I could not find any other. Note that the "dev" subdirectory is
	// guaranteed to be present, as it's always created by our parent
	// sysbox-runc.

	if err := os.Chdir("dev"); err != nil {
		return newSystemErrorWithCause(err, "chdir dev")
	}
	if err := os.Chdir(".."); err != nil {
		return newSystemErrorWithCause(err, "chdir ..")
	}

	return nil
}

// Returns the IP address(es) of the nameserver(ers) in the
// DNS resolver configuration file
func getDnsNameservers(resolvconf string) ([]string, error) {

	file, err := os.Open(resolvconf)
	if err != nil {
		return nil, newSystemErrorWithCausef(err, "opening %s", resolvconf)
	}
	defer file.Close()

	nameservers := []string{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		words := strings.Fields(line)
		if len(words) > 1 {
			if words[0] == "nameserver" {
				nameservers = append(nameservers, words[1])
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, newSystemErrorWithCausef(err, "scanning %s", resolvconf)
	}

	return nameservers, nil
}

// Returns the IP address of the container's default gateway
func getDefaultRoute() (string, error) {
	var ipStr string

	file, err := os.Open("/proc/net/route")
	if err != nil {
		return "", newSystemErrorWithCause(err, "opening /proc/net/route")
	}
	defer file.Close()

	// /proc/net/route:
	//
	// Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
	// eth0    00000000        010011AC        0003    0       0       0       00000000        0       0       0
	// eth0    000011AC        00000000        0001    0       0       0       0000FFFF        0       0       0

	scanner := bufio.NewScanner(file)
	line := 0

	for scanner.Scan() {

		// Skip header line
		if line < 1 {
			line++
			continue
		}

		// Skip if this is not a default route
		tokens := strings.Fields(scanner.Text())
		destIP := tokens[1]
		if destIP != "00000000" {
			continue
		}

		// Gateway address is field 2
		tokens = strings.Fields(scanner.Text())
		hexIP := "0x" + tokens[2]

		intIP, err := strconv.ParseInt(hexIP, 0, 64)
		if err != nil {
			return "", newSystemErrorWithCausef(err, "converting %s to int", hexIP)
		}
		uintIP := uint32(intIP)

		// Generate the IP address string
		//
		// TODO: ideally we should use host byte-order; the binary conversion
		// below is x86-specific.

		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uintIP)
		ipStr = net.IP(ip).String()

		break
	}

	return ipStr, nil
}

// Switches the IP address of the Docker DNS nameserver inside the container
// when it has localhost address (e.g., 127.0.0.11). This avoids DNS resolution
// problems with inner Docker containers. See Sysbox issue #679.
func switchDockerDnsIP(config *configs.Config, pipe io.ReadWriter) error {

	// Docker places a DNS resolver in containers deployed on custom bridge networks
	dockerDns := "127.0.0.11"

	resolvconf := "/etc/resolv.conf"
	if _, err := os.Stat(resolvconf); os.IsNotExist(err) {
		return nil
	}

	nameservers, err := getDnsNameservers(resolvconf)
	if err != nil {
		return err
	}

	needSwitch := false
	for _, ns := range nameservers {
		if ns == dockerDns {
			needSwitch = true
		}
	}

	if !needSwitch {
		return nil
	}

	defRoute, err := getDefaultRoute()
	if err != nil {
		return err
	}

	// Request the parent runc to enter the container's net-ns and change the DNS
	// in the iptables (can't do this from within the container as we may not
	// have the required / compatible iptables package in the container).
	reqs := []opReq{
		{
			Op:     switchDockerDns,
			OldDns: dockerDns,
			NewDns: defRoute,
		},
	}

	if err := syncParentDoOp(reqs, pipe); err != nil {
		return newSystemErrorWithCause(err, "syncing with parent runc to switch DNS IP")
	}

	oldData, err := ioutil.ReadFile(resolvconf)
	if err != nil {
		return newSystemErrorWithCausef(err, "reading %s", resolvconf)
	}

	newData := strings.Replace(string(oldData), dockerDns, defRoute, -1)

	// As we are about to write to resolv.conf, we should ensure that this one
	// is writable, which is not necessarily the case as file could have been
	// bind-mounted in RO mode (usually the case when 'readonly' spec attribute
	// is present). In these scenarios we will first remount the resource as RW,
	// and will remount it back to RO once the write operation is completed.
	var resolvconfMount *configs.Mount
	resolvcontDest := resolvconf[1:]
	for _, m := range config.Mounts {
		if m.Destination == resolvcontDest &&
			m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {
			if err := remountReadwrite(m); err != nil {
				return newSystemErrorWithCausef(err, "remounting %q as readwrite",
					m.Destination)
			}

			resolvconfMount = m
			break
		}
	}

	err = ioutil.WriteFile(resolvconf, []byte(newData), 0644)
	if err != nil {
		return newSystemErrorWithCausef(err, "writing %s", resolvconf)
	}

	// If applicable, flip resolvconfMount back to RO mode.
	if resolvconfMount != nil {
		if err := remountReadonly(resolvconfMount); err != nil {
			return newSystemErrorWithCausef(err, "remounting %q as readonly",
				resolvconfMount.Destination)
		}
	}

	// Enable routing of local-host addresses to ensure packets make it to the
	// Docker DNS (127.0.0.11:53).

	if err := ioutil.WriteFile("/proc/sys/net/ipv4/conf/all/route_localnet", []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enble routing of local-host addresses: %s", err)
	}

	return nil
}

// Function creates file-system state (i.e. files, dirs, softlinks) inside the
// container's rootfs, as required by Sysbox. Notice that the path of these fs
// components is with respect to the container's rootfs, so this instruction
// should be only called after pivot-root invokation.
func addFsState(config *configs.Config) error {

	for _, entry := range config.FsState {
		if err := entry.Add(); err != nil {
			return newSystemErrorWithCausef(err, "unable to create fsEntry %s", entry.GetPath())
		}
	}

	return nil
}
