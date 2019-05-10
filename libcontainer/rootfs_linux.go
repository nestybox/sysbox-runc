// +build linux

package libcontainer

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cyphar/filepath-securejoin"
	"github.com/mrunalp/fileutils"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/mount"
	"github.com/opencontainers/runc/libcontainer/system"
	libcontainerUtils "github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runc/libsysvisor/syscont"
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

	if err := prepareRoot(config); err != nil {
		return newSystemErrorWithCause(err, "preparing rootfs")
	}

	if config.ShiftUids {
		if err := mountShiftfsOnRootfs(config.Rootfs, pipe); err != nil {
			return newSystemErrorWithCause(err, "mounting shiftfs on rootfs")
		}
		if err := mountShiftfsOnBindSources(config, pipe); err != nil {
			return newSystemErrorWithCause(err, "mounting shiftfs on bind sources")
		}
	}

	if err := doMounts(config, pipe); err != nil {
		return newSystemErrorWithCause(err, "setting up rootfs mounts")
	}

	setupDev := needsSetupDev(config)
	if setupDev {
		if err := createDevices(config); err != nil {
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
	if config.NoPivotRoot {
		err = msMoveRoot(config.Rootfs)
	} else if config.Namespaces.Contains(configs.NEWNS) {
		err = pivotRoot(config.Rootfs)
	} else {
		err = chroot(config.Rootfs)
	}
	if err != nil {
		return newSystemErrorWithCause(err, "jailing process inside rootfs")
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

// finalizeRootfs sets anything to ro if necessary. You must call
// prepareRootfs first.
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

	unix.Umask(0022)
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

func prepareBindDest(m *configs.Mount, rootfs string, absDestPath bool) (err error) {
	var base, dest string

	if err := validateCwd(rootfs); err != nil {
		return newSystemErrorWithCause(err, "validating cwd")
	}

	// ensure that the destination of the bind mount is resolved of symlinks at mount time because
	// any previous mounts can invalidate the next mount's destination.
	// this can happen when a user specifies mounts within other mounts to cause breakouts or other
	// evil stuff to try to escape the container's rootfs.
	if absDestPath {
		base = rootfs
	} else {
		base = "."
	}

	if dest, err = securejoin.SecureJoin(base, m.Destination); err != nil {
		return err
	}

	// update the mount with the correct dest after symlinks are resolved.
	m.Destination = dest
	if err = createIfNotExists(dest, m.BindSrcIsDir); err != nil {
		return err
	}

	return nil
}

func mountToRootfs(m *configs.Mount, rootfs, mountLabel string, enableCgroupns, shiftfs bool, pipe io.ReadWriter) error {
	var (
		dest = m.Destination
	)

	// This function assumes cwd is the container's rootfs
	dest = filepath.Join(".", dest)
	m.Destination = dest

	switch m.Device {
	case "proc", "sysfs":
		if err := os.MkdirAll(dest, 0755); err != nil {
			return err
		}
		// Selinux kernels do not support labeling of /proc or /sys
		return mountPropagate(m, "")
	case "mqueue":
		if err := os.MkdirAll(dest, 0755); err != nil {
			return err
		}
		if err := mountPropagate(m, mountLabel); err != nil {
			// older kernels do not support labeling of /dev/mqueue
			if err := mountPropagate(m, ""); err != nil {
				return err
			}
			return label.SetFileLabel(dest, mountLabel)
		}
		return nil
	case "tmpfs":
		copyUp := m.Extensions&configs.EXT_COPYUP == configs.EXT_COPYUP
		tmpDir := ""
		stat, err := os.Stat(dest)
		if err != nil {
			if err := os.MkdirAll(dest, 0755); err != nil {
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
		return nil
	case "bind":
		// sysvisor-runc: in order to support uid shifting on bind mounts, we handle bind
		// mounts differently than the OCI runc; in particular, we perform the bind mount by
		// asking the parent runc to spawn a helper child process which enters the
		// container's mount namespace only and performs the mount. The helper process is
		// needed to overcome the problem whereby the container's init process has no search
		// permission to the bind mount source. Since this helper is not in the container's
		// user namespace, it has true root credentials and thus can access the bind mount
		// source yet perform the mount in the container's mount namespace.
		if err := prepareBindDest(m, rootfs, false); err != nil {
			return err
		}
		mountInfo := &mountReqInfo{
			Op:     bind,
			Mount:  *m,
			Label:  mountLabel,
			Rootfs: rootfs,
		}
		if err := syncParentDoMount(mountInfo, pipe); err != nil {
			return newSystemErrorWithCause(err, "sync parent do mount")
		}
	case "cgroup":
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
		if err := mountToRootfs(tmpfs, rootfs, mountLabel, enableCgroupns, shiftfs, pipe); err != nil {
			return err
		}
		for _, b := range binds {
			if enableCgroupns {
				subsystemPath := b.Destination
				if err := os.MkdirAll(subsystemPath, 0755); err != nil {
					return err
				}
				flags := defaultMountFlags
				if m.Flags&unix.MS_RDONLY != 0 {
					flags = flags | unix.MS_RDONLY
				}
				cgroupmount := &configs.Mount{
					Source:      "cgroup",
					Device:      "cgroup",
					Destination: subsystemPath,
					Flags:       flags,
					Data:        filepath.Base(subsystemPath),
				}
				if err := mountNewCgroup(cgroupmount); err != nil {
					return err
				}
			} else {
				if err := mountToRootfs(b, rootfs, mountLabel, enableCgroupns, shiftfs, pipe); err != nil {
					return err
				}
			}
		}
		for _, mc := range merged {
			for _, ss := range strings.Split(mc, ",") {
				// symlink(2) is very dumb, it will just shove the path into
				// the link and doesn't do any checks or relative path
				// conversion. Also, don't error out if the cgroup already exists.
				subsystemPath := filepath.Join(m.Destination, ss)
				if err := os.Symlink(mc, subsystemPath); err != nil && !os.IsExist(err) {
					return err
				}
			}
		}
		if m.Flags&unix.MS_RDONLY != 0 {
			// remount cgroup root as readonly
			mcgrouproot := &configs.Mount{
				Source:      m.Destination,
				Device:      "bind",
				Destination: m.Destination,
				Flags:       defaultMountFlags | unix.MS_RDONLY | unix.MS_BIND,
			}
			if err := remount(mcgrouproot); err != nil {
				return err
			}
		}
	default:
		// ensure that the destination of the mount is resolved of symlinks at mount time because
		// any previous mounts can invalidate the next mount's destination.
		// this can happen when a user specifies mounts within other mounts to cause breakouts or other
		// evil stuff to try to escape the container's rootfs.
		if err := os.MkdirAll(dest, 0755); err != nil {
			return err
		}
		return mountPropagate(m, mountLabel)
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
func createDevices(config *configs.Config) error {
	useBindMount := system.RunningInUserNS() || config.Namespaces.Contains(configs.NEWUSER)
	oldMask := unix.Umask(0000)
	for _, node := range config.Devices {
		// containers running in a user namespace are not allowed to mknod
		// devices so we can just bind mount it from the host.
		if err := createDeviceNode(node, useBindMount); err != nil {
			unix.Umask(oldMask)
			return err
		}
	}
	unix.Umask(oldMask)
	return nil
}

func bindMountDeviceNode(dest string, node *configs.Device) error {
	f, err := os.Create(dest)
	if err != nil && !os.IsExist(err) {
		return err
	}
	if f != nil {
		f.Close()
	}
	return unix.Mount(node.Path, dest, "bind", unix.MS_BIND, "")
}

// Creates the device node in the rootfs of the container.
func createDeviceNode(node *configs.Device, bind bool) error {
	dest := filepath.Join(".", node.Path)
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
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

func mknodDevice(dest string, node *configs.Device) error {
	fileMode := node.FileMode
	switch node.Type {
	case 'c', 'u':
		fileMode |= unix.S_IFCHR
	case 'b':
		fileMode |= unix.S_IFBLK
	case 'p':
		fileMode |= unix.S_IFIFO
	default:
		return fmt.Errorf("%c is not a valid device type for device %s", node.Type, node.Path)
	}
	if err := unix.Mknod(dest, uint32(fileMode), node.Mkdev()); err != nil {
		return err
	}
	return unix.Chown(dest, int(node.Uid), int(node.Gid))
}

func getMountInfo(mountinfo []*mount.Info, dir string) *mount.Info {
	for _, m := range mountinfo {
		if m.Mountpoint == dir {
			return m
		}
	}
	return nil
}

// Get the parent mount point of directory passed in as argument. Also return
// optional fields.
func getParentMount(rootfs string) (string, string, error) {
	var path string

	mountinfos, err := mount.GetMounts()
	if err != nil {
		return "", "", err
	}

	mountinfo := getMountInfo(mountinfos, rootfs)
	if mountinfo != nil {
		return rootfs, mountinfo.Optional, nil
	}

	path = rootfs
	for {
		path = filepath.Dir(path)

		mountinfo = getMountInfo(mountinfos, path)
		if mountinfo != nil {
			return path, mountinfo.Optional, nil
		}

		if path == "/" {
			break
		}
	}

	// If we are here, we did not find parent mount. Something is wrong.
	return "", "", fmt.Errorf("Could not find parent mount of %s", rootfs)
}

// Make parent mount private if it was shared
func rootfsParentMountPrivate(rootfs string) error {
	sharedMount := false

	parentMount, optionalOpts, err := getParentMount(rootfs)
	if err != nil {
		return err
	}

	optsSplit := strings.Split(optionalOpts, " ")
	for _, opt := range optsSplit {
		if strings.HasPrefix(opt, "shared:") {
			sharedMount = true
			break
		}
	}

	// Make parent mount PRIVATE if it was shared. It is needed for two
	// reasons. First of all pivot_root() will fail if parent mount is
	// shared. Secondly when we bind mount rootfs it will propagate to
	// parent namespace and we don't want that to happen.
	if sharedMount {
		return unix.Mount("", parentMount, "", unix.MS_PRIVATE, "")
	}

	return nil
}

func prepareRoot(config *configs.Config) error {
	flag := unix.MS_SLAVE | unix.MS_REC
	if config.RootPropagation != 0 {
		flag = config.RootPropagation
	}
	if err := unix.Mount("", "/", "", uintptr(flag), ""); err != nil {
		return err
	}

	// Make parent mount private to make sure following bind mount does
	// not propagate in other namespaces. Also it will help with kernel
	// check pass in pivot_root. (IS_SHARED(new_mnt->mnt_parent))
	if err := rootfsParentMountPrivate(config.Rootfs); err != nil {
		return err
	}

	if err := unix.Mount(".", ".", "bind", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}

	// in order for the mount to take effect on this current process, we need to re-open
	// the rootfs dir; otherwise the rootfs setup that follows fails (e.g., pivot_root()
	// reports an invalid argument error)
	if err := effectRootfsMount(); err != nil {
		return newSystemErrorWithCause(err, "effecting rootfs mount")
	}

	return nil
}

func setReadonly() error {
	return unix.Mount("/", "/", "bind", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, "")
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
	mountinfos, err := mount.GetMounts()
	if err != nil {
		return err
	}

	absRootfs, err := filepath.Abs(rootfs)
	if err != nil {
		return err
	}

	for _, info := range mountinfos {
		p, err := filepath.Abs(info.Mountpoint)
		if err != nil {
			return err
		}
		// Umount every syfs and proc file systems, except those under the container rootfs
		if (info.Fstype != "proc" && info.Fstype != "sysfs") || filepath.HasPrefix(p, absRootfs) {
			continue
		}
		// Be sure umount events are not propagated to the host.
		if err := unix.Mount("", p, "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
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
	if err := unix.Mount(rootfs, "/", "", unix.MS_MOVE, ""); err != nil {
		return err
	}
	return chroot(rootfs)
}

func chroot(rootfs string) error {
	if err := unix.Chroot("."); err != nil {
		return err
	}
	return unix.Chdir("/")
}

// createIfNotExists creates a file or a directory only if it does not already exist.
func createIfNotExists(path string, isDir bool) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			if isDir {
				return os.MkdirAll(path, 0755)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
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
func readonlyPath(path string) error {
	if err := unix.Mount(path, path, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return unix.Mount(path, path, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, "")
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
	return unix.Mount(m.Source, m.Destination, m.Device, uintptr(m.Flags|unix.MS_REMOUNT), "")
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

// sysvisor-runc: doMounts sets up all of the container's mounts as specified in the given config.
func doMounts(config *configs.Config, pipe io.ReadWriter) error {
	for _, m := range config.Mounts {
		for _, precmd := range m.PremountCmds {
			if err := mountCmd(precmd); err != nil {
				return newSystemErrorWithCause(err, "running premount command")
			}
		}
		if err := mountToRootfs(m, config.Rootfs, config.MountLabel, true, config.ShiftUids, pipe); err != nil {
			return newSystemErrorWithCausef(err, "mounting %q to rootfs %q at %q", m.Source, config.Rootfs, m.Destination)
		}
		for _, postcmd := range m.PostmountCmds {
			if err := mountCmd(postcmd); err != nil {
				return newSystemErrorWithCause(err, "running postmount command")
			}
		}
	}
	return nil
}

// sysvisor-runc: validateCwd verifies that the current working directory is the container's
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

// sysvisor-runc: allowShiftfsBindSource checks if the source dir of a bind mount is allowed
// when using shiftfs.
func allowShiftfsBindSource(source, rootfs string) error {

	// We do not allow bind mounts whose source is directly above the container's rootfs
	// (e.g., if the rootfs is at /a/b/c/d, we don't allow bind sources at /, /a, /a/b, or
	// /a/b/c; but we do allow them at /a/x, /a/b/x, or /a/b/c/x). The reason we disallow
	// such bind mounts is that when using uid-shifting we need to mount shiftfs on the
	// rootfs as well as the bind sources. If we where to allow bind sources directly above
	// rootfs, we would end with shiftfs-on-shiftfs which is not supported.
	if strings.Contains(rootfs, source) {
		return fmt.Errorf("bind mount with source at %v is above the container's rootfs at %v; this is not supported when using uid-shifting", source, rootfs)
	}

	// We don't support bind sources on tmpfs, due to problems with shiftfs-on-tmpfs mounts
	// (see github issue #123). However, we make an exception for Docker /dev/shm mounts
	// (i.e.bind mounts from a tmpfs dir in `/var/lib/docker/containers/<container-id>/mounts/shm`
	// to the container's `/dev/shm`) as these are commonly used by Docker and are not
	// affected by the github issue described above because the bind source directory is
	// known to be initially empty.
	if !strings.Contains(source, "/var/lib/docker/") {
		if mounted, err := mount.MountedWithFs(source, "tmpfs"); mounted || err != nil {
			if err != nil {
				return err
			} else {
				return fmt.Errorf("bind mount with source at %v is on tmpfs and requires uid-shifting; however mounting shiftfs on tmpfs is not supported", source)
			}
		}
	}

	return nil
}

// sysvisor-runc: effectRootfsMount ensure the calling process sees the effects of a previous rootfs
// mount. It does this by reopening the rootfs directory.
func effectRootfsMount() error {

	// The method for reopening the rootfs directory is pretty lame, but I could not find
	// any other. Note that per the Linux FHS, /dev is required on a Linux host and thus
	// will always be present in a system container
	if err := os.Chdir("dev"); err != nil {
		return newSystemErrorWithCause(err, "chdir bin")
	}
	if err := os.Chdir(".."); err != nil {
		return newSystemErrorWithCause(err, "chdir ..")
	}

	return nil
}

// sysvisor-runc: mountShiftfsOnRootfs mounts shiftfs over the container's rootfs.
// Since the shiftfs mount must be done by true root, mountShitfsOnRootfs requests the
// parent runc to do the mount.
func mountShiftfsOnRootfs(rootfs string, pipe io.ReadWriter) error {

	if mounted, err := mount.MountedWithFs(rootfs, "tmpfs"); mounted || err != nil {
		if err != nil {
			return err
		} else {
			return fmt.Errorf("rootfs %v is on tmpfs and requires uid-shifting; however mounting shiftfs on tmpfs is not supported", rootfs)
		}
	}

	mountInfo := &mountReqInfo{
		Op:     shiftRootfs,
		Rootfs: rootfs,
	}

	err := syncParentDoMount(mountInfo, pipe)
	if err != nil {
		return newSystemErrorWithCause(err, "syncing with parent runc to perform mount")
	}

	if err := effectRootfsMount(); err != nil {
		return newSystemErrorWithCause(err, "effecting rootfs mount")
	}

	return nil
}

// sysvisor-runc: mountShiftfs mounts shiftfs over the source of bind mounts. Since the
// shiftfs mount must be done by true root, it requests the parent runc to do the mount.
func mountShiftfsOnBindSources(config *configs.Config, pipe io.ReadWriter) error {

	// cleanup bind sources
	paths := []string{}
	for _, m := range config.Mounts {
		if m.Device == "bind" {

			// Don't mount shiftfs on bind sources under the container's rootfs
			if filepath.HasPrefix(m.Source, config.Rootfs) {
				continue
			}

			// sysvisor-fs handles uid(gid) shifting itself, so no need for mounting shiftfs on top
			if filepath.HasPrefix(m.Source, syscont.SysvisorFsDir) {
				continue
			}

			if err := allowShiftfsBindSource(m.Source, config.Rootfs); err != nil {
				return newSystemErrorWithCause(err, "validating bind source")
			}

			paths = append(paths, m.Source)
		}
	}

	if len(paths) == 0 {
		return nil
	}

	// To avoid shiftfs-on-shiftfs, if we see paths such as /x/y and /x/y/z, mount
	// shiftfs on /x/y only (i.e., the base path)
	sort.Slice(paths, func(i, j int) bool { return !filepath.HasPrefix(paths[i], paths[j]) })
	basePaths := []string{paths[0]}
	for i := 1; i < len(paths); i++ {
		found := false
		for _, b := range basePaths {
			if strings.Contains(paths[i], b) {
				found = true
			}
		}
		if !found {
			basePaths = append(basePaths, paths[i])
		}
	}

	mountInfo := &mountReqInfo{
		Op:    shiftBind,
		Paths: basePaths,
	}

	err := syncParentDoMount(mountInfo, pipe)
	if err != nil {
		return newSystemErrorWithCause(err, "syncing with parent runc to perform mount")
	}

	return nil
}
