// +build linux

package systemd

import (
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs2"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type unifiedManager struct {
	mu      sync.Mutex
	cgroups *configs.Cgroup
	// path is like "/sys/fs/cgroup/user.slice/user-1001.slice/session-1.scope"
	path     string
	rootless bool
}

func NewUnifiedManager(config *configs.Cgroup, path string, rootless bool) cgroups.Manager {
	return &unifiedManager{
		cgroups:  config,
		path:     path,
		rootless: rootless,
	}
}

// unifiedResToSystemdProps tries to convert from Cgroup.Resources.Unified
// key/value map (where key is cgroupfs file name) to systemd unit properties.
// This is on a best-effort basis, so the properties that are not known
// (to this function and/or systemd) are ignored (but logged with "debug"
// log level).
//
// For the list of keys, see https://www.kernel.org/doc/Documentation/cgroup-v2.txt
//
// For the list of systemd unit properties, see systemd.resource-control(5).
func unifiedResToSystemdProps(conn *systemdDbus.Conn, res map[string]string) (props []systemdDbus.Property, _ error) {
	var err error

	for k, v := range res {
		if strings.Contains(k, "/") {
			return nil, fmt.Errorf("unified resource %q must be a file name (no slashes)", k)
		}
		sk := strings.SplitN(k, ".", 2)
		if len(sk) != 2 {
			return nil, fmt.Errorf("unified resource %q must be in the form CONTROLLER.PARAMETER", k)
		}
		// Kernel is quite forgiving to extra whitespace
		// around the value, and so should we.
		v = strings.TrimSpace(v)
		// Please keep cases in alphabetical order.
		switch k {
		case "cpu.max":
			// value: quota [period]
			quota := int64(0) // 0 means "unlimited" for addCpuQuota, if period is set
			period := defCPUQuotaPeriod
			sv := strings.Fields(v)
			if len(sv) < 1 || len(sv) > 2 {
				return nil, fmt.Errorf("unified resource %q value invalid: %q", k, v)
			}
			// quota
			if sv[0] != "max" {
				quota, err = strconv.ParseInt(sv[0], 10, 64)
				if err != nil {
					return nil, fmt.Errorf("unified resource %q period value conversion error: %w", k, err)
				}
			}
			// period
			if len(sv) == 2 {
				period, err = strconv.ParseUint(sv[1], 10, 64)
				if err != nil {
					return nil, fmt.Errorf("unified resource %q quota value conversion error: %w", k, err)
				}
			}
			addCpuQuota(conn, &props, quota, period)

		case "cpu.weight":
			num, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("unified resource %q value conversion error: %w", k, err)
			}
			props = append(props,
				newProp("CPUWeight", num))

		case "cpuset.cpus", "cpuset.mems":
			bits, err := rangeToBits(v)
			if err != nil {
				return nil, fmt.Errorf("unified resource %q=%q conversion error: %w", k, v, err)
			}
			m := map[string]string{
				"cpuset.cpus": "AllowedCPUs",
				"cpuset.mems": "AllowedMemoryNodes",
			}
			// systemd only supports these properties since v244
			sdVer := systemdVersion(conn)
			if sdVer >= 244 {
				props = append(props,
					newProp(m[k], bits))
			} else {
				logrus.Debugf("systemd v%d is too old to support %s"+
					" (setting will still be applied to cgroupfs)",
					sdVer, m[k])
			}

		case "memory.high", "memory.low", "memory.min", "memory.max", "memory.swap.max":
			num := uint64(math.MaxUint64)
			if v != "max" {
				num, err = strconv.ParseUint(v, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("unified resource %q value conversion error: %w", k, err)
				}
			}
			m := map[string]string{
				"memory.high":     "MemoryHigh",
				"memory.low":      "MemoryLow",
				"memory.min":      "MemoryMin",
				"memory.max":      "MemoryMax",
				"memory.swap.max": "MemorySwapMax",
			}
			props = append(props,
				newProp(m[k], num))

		case "pids.max":
			num := uint64(math.MaxUint64)
			if v != "max" {
				var err error
				num, err = strconv.ParseUint(v, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("unified resource %q value conversion error: %w", k, err)
				}
			}
			props = append(props,
				newProp("TasksAccounting", true),
				newProp("TasksMax", num))

		case "memory.oom.group":
			// Setting this to 1 is roughly equivalent to OOMPolicy=kill
			// (as per systemd.service(5) and
			// https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html),
			// but it's not clear what to do if it is unset or set
			// to 0 in runc update, as there are two other possible
			// values for OOMPolicy (continue/stop).
			fallthrough

		default:
			// Ignore the unknown resource here -- will still be
			// applied in Set which calls fs2.Set.
			logrus.Debugf("don't know how to convert unified resource %q=%q to systemd unit property; skipping (will still be applied to cgroupfs)", k, v)
		}
	}

	return props, nil
}

func genV2ResourcesProperties(c *configs.Cgroup, conn *systemdDbus.Conn) ([]systemdDbus.Property, error) {
	var properties []systemdDbus.Property
	r := c.Resources

	// NOTE: This is of questionable correctness because we insert our own
	//       devices eBPF program later. Two programs with identical rules
	//       aren't the end of the world, but it is a bit concerning. However
	//       it's unclear if systemd removes all eBPF programs attached when
	//       doing SetUnitProperties...
	deviceProperties, err := generateDeviceProperties(r.Devices)
	if err != nil {
		return nil, err
	}
	properties = append(properties, deviceProperties...)

	if r.Memory != 0 {
		properties = append(properties,
			newProp("MemoryMax", uint64(r.Memory)))
	}
	if r.MemoryReservation != 0 {
		properties = append(properties,
			newProp("MemoryLow", uint64(r.MemoryReservation)))
	}

	swap, err := cgroups.ConvertMemorySwapToCgroupV2Value(r.MemorySwap, r.Memory)
	if err != nil {
		return nil, err
	}
	if swap != 0 {
		properties = append(properties,
			newProp("MemorySwapMax", uint64(swap)))
	}

	if r.CpuWeight != 0 {
		properties = append(properties,
			newProp("CPUWeight", r.CpuWeight))
	}

	addCpuQuota(conn, &properties, r.CpuQuota, r.CpuPeriod)

	if r.PidsLimit > 0 || r.PidsLimit == -1 {
		properties = append(properties,
			newProp("TasksAccounting", true),
			newProp("TasksMax", uint64(r.PidsLimit)))
	}

	err = addCpuset(conn, &properties, r.CpusetCpus, r.CpusetMems)
	if err != nil {
		return nil, err
	}

	// ignore r.KernelMemory

	// convert Resources.Unified map to systemd properties
	if r.Unified != nil {
		unifiedProps, err := unifiedResToSystemdProps(conn, r.Unified)
		if err != nil {
			return nil, err
		}
		properties = append(properties, unifiedProps...)
	}

	return properties, nil
}

func (m *unifiedManager) Apply(pid int) error {
	var (
		c          = m.cgroups
		unitName   = getUnitName(c)
		properties []systemdDbus.Property
	)

	if c.Paths != nil {
		return cgroups.WriteCgroupProc(m.path, pid)
	}

	slice := "system.slice"
	if m.rootless {
		slice = "user.slice"
	}
	if c.Parent != "" {
		slice = c.Parent
	}

	properties = append(properties, systemdDbus.PropDescription("libcontainer container "+c.Name))

	// if we create a slice, the parent is defined via a Wants=
	if strings.HasSuffix(unitName, ".slice") {
		properties = append(properties, systemdDbus.PropWants(slice))
	} else {
		// otherwise, we use Slice=
		properties = append(properties, systemdDbus.PropSlice(slice))
	}

	// only add pid if its valid, -1 is used w/ general slice creation.
	if pid != -1 {
		properties = append(properties, newProp("PIDs", []uint32{uint32(pid)}))
	}

	// sysbox-runc requires service or scope units for the container, as otherwise delegation won't work.
	if strings.HasSuffix(unitName, ".slice") {
		return fmt.Errorf("container cgroup is on systemd slice unit %s; sysbox-runc requires it to be on systemd service or scope units in order for cgroup delegation to work", unitName)
	}

	// sysbox-runc requires cgroup delegation, which is supported on systemd versions >= 218.
	dbusConnection, err := getDbusConnection(false)
	if err != nil {
		return err
	}

	sdVer := systemdVersion(dbusConnection)
	if sdVer < 218 {
		return fmt.Errorf("systemd version is < 218; sysbox-runc requires version >= 218 for cgroup delegation.")
	}

	properties = append(properties, newProp("Delegate", true))

	// Always enable accounting, this gets us the same behaviour as the fs implementation,
	// plus the kernel has some problems with joining the memory cgroup at a later time.
	properties = append(properties,
		newProp("MemoryAccounting", true),
		newProp("CPUAccounting", true),
		newProp("IOAccounting", true))

	// Assume DefaultDependencies= will always work (the check for it was previously broken.)
	properties = append(properties,
		newProp("DefaultDependencies", false))

	resourcesProperties, err := genV2ResourcesProperties(c, dbusConnection)
	if err != nil {
		return err
	}
	properties = append(properties, resourcesProperties...)
	properties = append(properties, c.SystemdProps...)

	if err := startUnit(dbusConnection, unitName, properties); err != nil {
		return errors.Wrapf(err, "error while starting unit %q with properties %+v", unitName, properties)
	}

	if err = m.initPath(); err != nil {
		return err
	}
	if err := fs2.CreateCgroupPath(m.path, m.cgroups); err != nil {
		return err
	}
	return nil
}

func (m *unifiedManager) Destroy() error {
	if m.cgroups.Paths != nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	dbusConnection, err := getDbusConnection(m.rootless)
	if err != nil {
		return err
	}
	unitName := getUnitName(m.cgroups)
	if err := stopUnit(dbusConnection, unitName); err != nil {
		return err
	}

	// XXX this is probably not needed, systemd should handle it
	err = os.Remove(m.path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

func (m *unifiedManager) Path(_ string) string {
	return m.path
}

// getSliceFull value is used in initPath.
// The value is incompatible with systemdDbus.PropSlice.
func (m *unifiedManager) getSliceFull() (string, error) {
	c := m.cgroups
	slice := "system.slice"
	if m.rootless {
		slice = "user.slice"
	}
	if c.Parent != "" {
		var err error
		slice, err = ExpandSlice(c.Parent)
		if err != nil {
			return "", err
		}
	}

	if m.rootless {
		dbusConnection, err := getDbusConnection(m.rootless)
		if err != nil {
			return "", err
		}
		// managerCGQuoted is typically "/user.slice/user-${uid}.slice/user@${uid}.service" including the quote symbols
		managerCGQuoted, err := dbusConnection.GetManagerProperty("ControlGroup")
		if err != nil {
			return "", err
		}
		managerCG, err := strconv.Unquote(managerCGQuoted)
		if err != nil {
			return "", err
		}
		slice = filepath.Join(managerCG, slice)
	}

	// an example of the final slice in rootless: "/user.slice/user-1001.slice/user@1001.service/user.slice"
	// NOTE: systemdDbus.PropSlice requires the "/user.slice/user-1001.slice/user@1001.service/" prefix NOT to be specified.
	return slice, nil
}

func (m *unifiedManager) initPath() error {
	if m.path != "" {
		return nil
	}

	sliceFull, err := m.getSliceFull()
	if err != nil {
		return err
	}

	c := m.cgroups
	path := filepath.Join(sliceFull, getUnitName(c))
	path, err = securejoin.SecureJoin(fs2.UnifiedMountpoint, path)
	if err != nil {
		return err
	}

	// an example of the final path in rootless:
	// "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/user.slice/libpod-132ff0d72245e6f13a3bbc6cdc5376886897b60ac59eaa8dea1df7ab959cbf1c.scope"
	m.path = path

	return nil
}

func (m *unifiedManager) fsManager() (cgroups.Manager, error) {
	if err := m.initPath(); err != nil {
		return nil, err
	}
	return fs2.NewManager(m.cgroups, m.path, m.rootless)
}

func (m *unifiedManager) Freeze(state configs.FreezerState) error {
	fsMgr, err := m.fsManager()
	if err != nil {
		return err
	}
	return fsMgr.Freeze(state)
}

func (m *unifiedManager) GetPids() ([]int, error) {
	if err := m.initPath(); err != nil {
		return nil, err
	}
	return cgroups.GetPids(m.path)
}

func (m *unifiedManager) GetAllPids() ([]int, error) {
	if err := m.initPath(); err != nil {
		return nil, err
	}
	return cgroups.GetAllPids(m.path)
}

func (m *unifiedManager) GetStats() (*cgroups.Stats, error) {
	fsMgr, err := m.fsManager()
	if err != nil {
		return nil, err
	}
	return fsMgr.GetStats()
}

func (m *unifiedManager) Set(container *configs.Config) error {
	dbusConnection, err := getDbusConnection(m.rootless)
	if err != nil {
		return err
	}
	properties, err := genV2ResourcesProperties(m.cgroups, dbusConnection)
	if err != nil {
		return err
	}

	// We have to freeze the container while systemd sets the cgroup settings.
	// The reason for this is that systemd's application of DeviceAllow rules
	// is done disruptively, resulting in spurrious errors to common devices
	// (unlike our fs driver, they will happily write deny-all rules to running
	// containers). So we freeze the container to avoid them hitting the cgroup
	// error. But if the freezer cgroup isn't supported, we just warn about it.
	targetFreezerState := configs.Undefined
	if !m.cgroups.SkipDevices {
		// Figure out the current freezer state, so we can revert to it after we
		// temporarily freeze the container.
		targetFreezerState, err = m.GetFreezerState()
		if err != nil {
			return err
		}
		if targetFreezerState == configs.Undefined {
			targetFreezerState = configs.Thawed
		}

		if err := m.Freeze(configs.Frozen); err != nil {
			logrus.Infof("freeze container before SetUnitProperties failed: %v", err)
		}
	}

	if err := dbusConnection.SetUnitProperties(getUnitName(m.cgroups), true, properties...); err != nil {
		_ = m.Freeze(targetFreezerState)
		return errors.Wrap(err, "error while setting unit properties")
	}

	// Reset freezer state before we apply the configuration, to avoid clashing
	// with the freezer setting in the configuration.
	_ = m.Freeze(targetFreezerState)

	fsMgr, err := m.fsManager()
	if err != nil {
		return err
	}
	return fsMgr.Set(container)
}

func (m *unifiedManager) GetPaths() map[string]string {
	paths := make(map[string]string, 1)
	paths[""] = m.path
	return paths
}

func (m *unifiedManager) GetCgroups() (*configs.Cgroup, error) {
	return m.cgroups, nil
}

func (m *unifiedManager) GetFreezerState() (configs.FreezerState, error) {
	fsMgr, err := m.fsManager()
	if err != nil {
		return configs.Undefined, err
	}
	return fsMgr.GetFreezerState()
}

func (m *unifiedManager) Exists() bool {
	return cgroups.PathExists(m.path)
}

func (m *unifiedManager) CreateChildCgroup(config *configs.Config) error {

	// Change the cgroup ownership to match the root user in the system
	// container (needed for delegation).
	path := m.path

	rootuid, err := config.HostRootUID()
	if err != nil {
		return err
	}
	rootgid, err := config.HostRootGID()
	if err != nil {
		return err
	}

	if err := os.Chown(path, rootuid, rootgid); err != nil {
		return fmt.Errorf("Failed to change owner of cgroup %s", path)
	}

	// Change ownership of some of the files inside the sys container's cgroup;
	// for cgroups v2 we only change the ownership of a subset of the files, as
	// specified in section "Cgroups Delegation: Delegating a Hierarchy to a Less
	// Privileged User" in cgroups(7).
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	for _, file := range files {
		fname := file.Name()

		if fname == "cgroup.procs" ||
			fname == "cgroup.subtree_control" ||
			fname == "cgroup.threads" {

			absFileName := filepath.Join(path, fname)
			if err := os.Chown(absFileName, rootuid, rootgid); err != nil {
				return fmt.Errorf("Failed to change owner for file %s", absFileName)
			}
		}
	}

	// Create a leaf cgroup to be used for the sys container's init process (and
	// for all its child processes). Its purpose is to prevent processes from
	// living in the sys container's cgroup root, because once inner sub-cgroups are
	// created, the kernel considers the sys container's cgroup root an
	// intermediate node in the global cgroup hierarchy. This in turn forces all
	// sub-groups inside the sys container to be of "domain-invalid" type (and
	// thus prevents domain cgroup controllers such as the memory controller
	// from being applied inside the sys container).
	//
	// We choose the name "init.scope" for the leaf cgroup because it works well
	// in sys containers that carry systemd, as well as those that don't. In both
	// cases, the sys container's init processes are placed in the init.scope
	// cgroup. For sys container's with systemd, systemd then moves the processes
	// to other sub-cgroups it manages.
	//
	// Note that processes that enter the sys container via "exec" will also
	// be placed in this sub-cgroup.

	leafPath := filepath.Join(path, "init.scope")
	if err = os.MkdirAll(leafPath, 0755); err != nil {
		return err
	}

	if err := os.Chown(leafPath, rootuid, rootgid); err != nil {
		return fmt.Errorf("Failed to change owner of cgroup %s", leafPath)
	}

	files, err = ioutil.ReadDir(leafPath)
	if err != nil {
		return err
	}
	for _, file := range files {
		fname := file.Name()

		if fname == "cgroup.procs" ||
			fname == "cgroup.subtree_control" ||
			fname == "cgroup.threads" {

			absFileName := filepath.Join(leafPath, fname)
			if err := os.Chown(absFileName, rootuid, rootgid); err != nil {
				return fmt.Errorf("Failed to change owner for file %s", absFileName)
			}
		}
	}

	return nil
}

func (m *unifiedManager) ApplyChildCgroup(pid int) error {
	paths := make(map[string]string, 1)
	paths[""] = filepath.Join(m.path, "init.scope")
	return cgroups.EnterPid(paths, pid)
}

func (m *unifiedManager) GetChildCgroupPaths() map[string]string {
	return m.GetPaths()
}

func (m *unifiedManager) GetType() cgroups.CgroupType {
	return cgroups.Cgroup_v2_systemd
}
