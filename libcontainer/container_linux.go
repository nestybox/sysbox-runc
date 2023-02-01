//go:build linux
// +build linux

package libcontainer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"

	"github.com/nestybox/sysbox-libs/mount"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/intelrdt"
	"github.com/opencontainers/runc/libcontainer/logs"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runc/libsysbox/sysbox"
	"github.com/opencontainers/runc/libsysbox/syscont"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/checkpoint-restore/go-criu/v4"
	criurpc "github.com/checkpoint-restore/go-criu/v4/rpc"

	"github.com/golang/protobuf/proto"

	errorsf "github.com/pkg/errors"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/nestybox/sysbox-libs/idMap"
	sh "github.com/nestybox/sysbox-libs/idShiftUtils"
	"github.com/nestybox/sysbox-libs/shiftfs"
)

const stdioFdCount = 3

type linuxContainer struct {
	id                   string
	root                 string
	config               *configs.Config
	cgroupManager        cgroups.Manager
	intelRdtManager      intelrdt.Manager
	initPath             string
	initArgs             []string
	initProcess          parentProcess
	initProcessStartTime uint64
	criuPath             string
	newuidmapPath        string
	newgidmapPath        string
	m                    sync.Mutex
	criuVersion          int
	state                containerState
	created              time.Time
	sysFs                *sysbox.Fs
	sysMgr               *sysbox.Mgr
}

// State represents a running container's state
type State struct {
	BaseState

	// Platform specific fields below here

	// Specified if the container was started under the rootless mode.
	// Set to true if BaseState.Config.RootlessEUID && BaseState.Config.RootlessCgroups
	Rootless bool `json:"rootless"`

	// Paths to all the container's cgroups, as returned by (*cgroups.Manager).GetPaths
	//
	// For cgroup v1, a key is cgroup subsystem name, and the value is the path
	// to the cgroup for this subsystem.
	//
	// For cgroup v2 unified hierarchy, a key is "", and the value is the unified path.
	CgroupPaths map[string]string `json:"cgroup_paths"`

	// NamespacePaths are filepaths to the container's namespaces. Key is the namespace type
	// with the value as the path.
	NamespacePaths map[configs.NamespaceType]string `json:"namespace_paths"`

	// Container's standard descriptors (std{in,out,err}), needed for checkpoint and restore
	ExternalDescriptors []string `json:"external_descriptors,omitempty"`

	// Intel RDT "resource control" filesystem path
	IntelRdtPath string `json:"intel_rdt_path"`

	// SysFs contains info about resources obtained from sysbox-fs
	SysFs sysbox.Fs `json:"sys_fs,omitempty"`

	// SysMgr contains info about resources obtained from sysbox-mgr
	SysMgr sysbox.Mgr `json:"sys_mgr,omitempty"`
}

// Container is a libcontainer container object.
//
// Each container is thread-safe within the same process. Since a container can
// be destroyed by a separate process, any function may return that the container
// was not found.
type Container interface {
	BaseContainer

	// Methods below here are platform specific

	// Checkpoint checkpoints the running container's state to disk using the criu(8) utility.
	//
	// errors:
	// Systemerror - System error.
	Checkpoint(criuOpts *CriuOpts) error

	// Restore restores the checkpointed container to a running state using the criu(8) utility.
	//
	// errors:
	// Systemerror - System error.
	Restore(process *Process, criuOpts *CriuOpts) error

	// If the Container state is RUNNING or CREATED, sets the Container state to PAUSING and pauses
	// the execution of any user processes. Asynchronously, when the container finished being paused the
	// state is changed to PAUSED.
	// If the Container state is PAUSED, do nothing.
	//
	// errors:
	// ContainerNotExists - Container no longer exists,
	// ContainerNotRunning - Container not running or created,
	// Systemerror - System error.
	Pause() error

	// If the Container state is PAUSED, resumes the execution of any user processes in the
	// Container before setting the Container state to RUNNING.
	// If the Container state is RUNNING, do nothing.
	//
	// errors:
	// ContainerNotExists - Container no longer exists,
	// ContainerNotPaused - Container is not paused,
	// Systemerror - System error.
	Resume() error

	// NotifyOOM returns a read-only channel signaling when the container receives an OOM notification.
	//
	// errors:
	// Systemerror - System error.
	NotifyOOM() (<-chan struct{}, error)

	// NotifyMemoryPressure returns a read-only channel signaling when the container reaches a given pressure level
	//
	// errors:
	// Systemerror - System error.
	NotifyMemoryPressure(level PressureLevel) (<-chan struct{}, error)
}

// ID returns the container's unique ID
func (c *linuxContainer) ID() string {
	return c.id
}

// Config returns the container's configuration
func (c *linuxContainer) Config() configs.Config {
	return *c.config
}

func (c *linuxContainer) Status() (Status, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentStatus()
}

func (c *linuxContainer) State() (*State, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentState()
}

func (c *linuxContainer) OCIState() (*specs.State, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentOCIState()
}

func (c *linuxContainer) Processes() ([]int, error) {
	var pids []int
	status, err := c.currentStatus()
	if err != nil {
		return pids, err
	}
	// for systemd cgroup, the unit's cgroup path will be auto removed if container's all processes exited
	if status == Stopped && !c.cgroupManager.Exists() {
		return pids, nil
	}

	pids, err = c.cgroupManager.GetAllPids()
	if err != nil {
		return nil, newSystemErrorWithCause(err, "getting all container pids from cgroups")
	}
	return pids, nil
}

func (c *linuxContainer) Stats() (*Stats, error) {
	var (
		err   error
		stats = &Stats{}
	)
	if stats.CgroupStats, err = c.cgroupManager.GetStats(); err != nil {
		return stats, newSystemErrorWithCause(err, "getting container stats from cgroups")
	}
	if c.intelRdtManager != nil {
		if stats.IntelRdtStats, err = c.intelRdtManager.GetStats(); err != nil {
			return stats, newSystemErrorWithCause(err, "getting container's Intel RDT stats")
		}
	}
	for _, iface := range c.config.Networks {
		switch iface.Type {
		case "veth":
			istats, err := getNetworkInterfaceStats(iface.HostInterfaceName)
			if err != nil {
				return stats, newSystemErrorWithCausef(err, "getting network stats for interface %q", iface.HostInterfaceName)
			}
			stats.Interfaces = append(stats.Interfaces, istats)
		}
	}
	return stats, nil
}

func (c *linuxContainer) Set(config configs.Config) error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	if status == Stopped {
		return newGenericError(errors.New("container not running"), ContainerNotRunning)
	}
	if err := c.cgroupManager.Set(&config); err != nil {
		logrus.Warnf("Setting cgroup configs failed due to error: %v", err)
		// Set configs back
		if err2 := c.cgroupManager.Set(c.config); err2 != nil {
			logrus.Warnf("Setting back cgroup configs failed due to error: %v, your state.json and actual configs might be inconsistent.", err2)
		}
		return err
	}
	if c.intelRdtManager != nil {
		if err := c.intelRdtManager.Set(&config); err != nil {
			// Set configs back
			if err2 := c.cgroupManager.Set(c.config); err2 != nil {
				logrus.Warnf("Setting back cgroup configs failed due to error: %v, your state.json and actual configs might be inconsistent.", err2)
			}
			if err2 := c.intelRdtManager.Set(c.config); err2 != nil {
				logrus.Warnf("Setting back intelrdt configs failed due to error: %v, your state.json and actual configs might be inconsistent.", err2)
			}
			return err
		}
	}
	// After config setting succeed, update config and states
	c.config = &config
	_, err = c.updateState(nil)
	return err
}

func (c *linuxContainer) Start(process *Process) error {
	c.m.Lock()
	defer c.m.Unlock()

	config := c.config

	if config.Cgroups.Resources.SkipDevices {
		return newGenericError(errors.New("can't start container with SkipDevices set"), ConfigInvalid)
	}

	if process.Init {
		if err := c.createExecFifo(); err != nil {
			return err
		}

		//
		// Set up ID-shifting for the rootfs and bind-mounts
		//

		// Chown (rootfs only)
		if config.RootfsUidShiftType == sh.Chown {
			if config.RootfsCloned {
				uidOffset := int32(config.UidMappings[0].HostID)
				gidOffset := int32(config.GidMappings[0].HostID)
				if err := c.sysMgr.ChownClonedRootfs(uidOffset, gidOffset); err != nil {
					return newSystemErrorWithCause(err, "failed to chown rootfs clone")
				}
			} else {
				if err := c.chownRootfs(); err != nil {
					return err
				}
			}
		}

		// ID-mapping
		if err := c.setupIDMappedMounts(); err != nil {
			return err
		}

		// Shiftfs (will only act if mount is not marked for ID-mapping already)
		if err := c.setupShiftfsMarks(); err != nil {
			return err
		}
	}

	if err := c.start(process); err != nil {
		if process.Init {
			c.deleteExecFifo()
		}
		return err
	}
	return nil
}

func (c *linuxContainer) Run(process *Process) error {
	if err := c.Start(process); err != nil {
		return err
	}
	if process.Init {
		return c.exec()
	}
	return nil
}

func (c *linuxContainer) Exec() error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.exec()
}

func (c *linuxContainer) exec() error {
	path := filepath.Join(c.root, execFifoFilename)
	pid := c.initProcess.pid()
	blockingFifoOpenCh := awaitFifoOpen(path)
	for {
		select {
		case result := <-blockingFifoOpenCh:
			return handleFifoResult(result)

		case <-time.After(time.Millisecond * 100):
			stat, err := system.Stat(pid)
			if err != nil || stat.State == system.Zombie {
				// could be because process started, ran, and completed between our 100ms timeout and our system.Stat() check.
				// see if the fifo exists and has data (with a non-blocking open, which will succeed if the writing process is complete).
				if err := handleFifoResult(fifoOpen(path, false)); err != nil {
					return errors.New("container process is already dead")
				}
				return nil
			}
		}
	}
}

func readFromExecFifo(execFifo io.Reader) error {
	data, err := ioutil.ReadAll(execFifo)
	if err != nil {
		return err
	}
	if len(data) <= 0 {
		return errors.New("cannot start an already running container")
	}
	return nil
}

func awaitFifoOpen(path string) <-chan openResult {
	fifoOpened := make(chan openResult)
	go func() {
		result := fifoOpen(path, true)
		fifoOpened <- result
	}()
	return fifoOpened
}

func fifoOpen(path string, block bool) openResult {
	flags := os.O_RDONLY
	if !block {
		flags |= unix.O_NONBLOCK
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return openResult{err: newSystemErrorWithCause(err, "open exec fifo for reading")}
	}
	return openResult{file: f}
}

func handleFifoResult(result openResult) error {
	if result.err != nil {
		return result.err
	}
	f := result.file
	defer f.Close()
	if err := readFromExecFifo(f); err != nil {
		return err
	}
	return os.Remove(f.Name())
}

type openResult struct {
	file *os.File
	err  error
}

func (c *linuxContainer) start(process *Process) error {
	parent, err := c.newParentProcess(process)
	if err != nil {
		return newSystemErrorWithCause(err, "creating new parent process")
	}
	parent.forwardChildLogs()
	if err := parent.start(); err != nil {
		return newSystemErrorWithCause(err, "starting container process")
	}

	// generate a timestamp indicating when the container was started
	c.created = time.Now().UTC()

	// sysbox-runc: send the creation-timestamp to sysbox-fs.
	if process.Init && c.sysFs.Enabled() {
		if err := c.sysFs.SendCreationTime(c.created); err != nil {
			return newSystemErrorWithCause(err, "sending creation timestamp to sysbox-fs")
		}
	}

	if process.Init {
		c.state = &createdState{
			c: c,
		}
		state, err := c.updateState(parent)
		if err != nil {
			return err
		}
		c.initProcessStartTime = state.InitProcessStartTime

		if c.config.Hooks != nil {
			s, err := c.currentOCIState()
			if err != nil {
				return err
			}

			if err := c.config.Hooks[configs.Poststart].RunHooks(s); err != nil {
				if err := ignoreTerminateErrors(parent.terminate()); err != nil {
					logrus.Warn(errorsf.Wrapf(err, "Running Poststart hook"))
				}
				return err
			}
		}

		// sysbox-runc: send an update to sysbox-mgr with the container's config
		if c.sysMgr.Enabled() {
			userns := state.NamespacePaths[configs.NEWUSER]
			netns := state.NamespacePaths[configs.NEWNET]

			// Cast IDMap to LinuxIDMapping
			cast := func(m configs.IDMap) specs.LinuxIDMapping {
				return specs.LinuxIDMapping{
					ContainerID: uint32(m.ContainerID),
					HostID:      uint32(m.HostID),
					Size:        uint32(m.Size),
				}
			}

			uidMappings := []specs.LinuxIDMapping{}
			for _, m := range state.BaseState.Config.UidMappings {
				uidMappings = append(uidMappings, cast(m))
			}

			gidMappings := []specs.LinuxIDMapping{}
			for _, m := range state.BaseState.Config.GidMappings {
				gidMappings = append(gidMappings, cast(m))
			}

			if err := c.sysMgr.Update(userns, netns, uidMappings, gidMappings); err != nil {
				return newSystemErrorWithCause(err, "sending creation timestamp to sysbox-fs")
			}
		}
	}

	return nil
}

func (c *linuxContainer) Signal(s os.Signal, all bool) error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	if all {
		// for systemd cgroup, the unit's cgroup path will be auto removed if container's all processes exited
		if status == Stopped && !c.cgroupManager.Exists() {
			return nil
		}
		return signalAllProcesses(c.cgroupManager, s)
	}
	// to avoid a PID reuse attack
	if status == Running || status == Created || status == Paused {
		if err := c.initProcess.signal(s); err != nil {
			return newSystemErrorWithCause(err, "signaling init process")
		}
		return nil
	}
	return newGenericError(errors.New("container not running"), ContainerNotRunning)
}

func (c *linuxContainer) createExecFifo() error {
	rootuid, err := c.Config().HostRootUID()
	if err != nil {
		return err
	}
	rootgid, err := c.Config().HostRootGID()
	if err != nil {
		return err
	}

	fifoName := filepath.Join(c.root, execFifoFilename)
	if _, err := os.Stat(fifoName); err == nil {
		return fmt.Errorf("exec fifo %s already exists", fifoName)
	}
	oldMask := unix.Umask(0000)
	if err := unix.Mkfifo(fifoName, 0622); err != nil {
		unix.Umask(oldMask)
		return err
	}
	unix.Umask(oldMask)
	return os.Chown(fifoName, rootuid, rootgid)
}

func (c *linuxContainer) deleteExecFifo() {
	fifoName := filepath.Join(c.root, execFifoFilename)
	os.Remove(fifoName)
}

// includeExecFifo opens the container's execfifo as a pathfd, so that the
// container cannot access the statedir (and the FIFO itself remains
// un-opened). It then adds the FifoFd to the given exec.Cmd as an inherited
// fd, with _LIBCONTAINER_FIFOFD set to its fd number.
func (c *linuxContainer) includeExecFifo(cmd *exec.Cmd) error {
	fifoName := filepath.Join(c.root, execFifoFilename)
	fifoFd, err := unix.Open(fifoName, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}

	cmd.ExtraFiles = append(cmd.ExtraFiles, os.NewFile(uintptr(fifoFd), fifoName))
	cmd.Env = append(cmd.Env,
		"_LIBCONTAINER_FIFOFD="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1))
	return nil
}

func (c *linuxContainer) newParentProcess(p *Process) (parentProcess, error) {
	parentInitPipe, childInitPipe, err := utils.NewSockPair("init")
	if err != nil {
		return nil, newSystemErrorWithCause(err, "creating new init pipe")
	}
	messageSockPair := filePair{parentInitPipe, childInitPipe}

	parentLogPipe, childLogPipe, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("Unable to create the log pipe:  %s", err)
	}
	logFilePair := filePair{parentLogPipe, childLogPipe}

	cmd := c.commandTemplate(p, childInitPipe, childLogPipe)
	if !p.Init {
		return c.newSetnsProcess(p, cmd, messageSockPair, logFilePair)
	}

	// We only set up fifoFd if we're not doing a `runc exec`. The historic
	// reason for this is that previously we would pass a dirfd that allowed
	// for container rootfs escape (and not doing it in `runc exec` avoided
	// that problem), but we no longer do that. However, there's no need to do
	// this for `runc exec` so we just keep it this way to be safe.
	if err := c.includeExecFifo(cmd); err != nil {
		return nil, newSystemErrorWithCause(err, "including execfifo in cmd.Exec setup")
	}
	return c.newInitProcess(p, cmd, messageSockPair, logFilePair)
}

func (c *linuxContainer) commandTemplate(p *Process, childInitPipe *os.File, childLogPipe *os.File) *exec.Cmd {
	cmd := exec.Command(c.initPath, c.initArgs[1:]...)
	cmd.Args[0] = c.initArgs[0]
	cmd.Stdin = p.Stdin
	cmd.Stdout = p.Stdout
	cmd.Stderr = p.Stderr
	cmd.Dir = c.config.Rootfs
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &unix.SysProcAttr{}
	}
	cmd.Env = append(cmd.Env, "GOMAXPROCS="+os.Getenv("GOMAXPROCS"))
	cmd.ExtraFiles = append(cmd.ExtraFiles, p.ExtraFiles...)
	if p.ConsoleSocket != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, p.ConsoleSocket)
		cmd.Env = append(cmd.Env,
			"_LIBCONTAINER_CONSOLE="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
		)
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, childInitPipe)
	cmd.Env = append(cmd.Env,
		"_LIBCONTAINER_INITPIPE="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
		"_LIBCONTAINER_STATEDIR="+c.root,
	)

	cmd.ExtraFiles = append(cmd.ExtraFiles, childLogPipe)
	cmd.Env = append(cmd.Env,
		"_LIBCONTAINER_LOGPIPE="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
		"_LIBCONTAINER_LOGLEVEL="+p.LogLevel,
	)

	// NOTE: when running a container with no PID namespace and the parent process spawning the container is
	// PID1 the pdeathsig is being delivered to the container's init process by the kernel for some reason
	// even with the parent still running.
	if c.config.ParentDeathSignal > 0 {
		cmd.SysProcAttr.Pdeathsig = unix.Signal(c.config.ParentDeathSignal)
	}
	return cmd
}

func (c *linuxContainer) newInitProcess(p *Process, cmd *exec.Cmd, messageSockPair, logFilePair filePair) (*initProcess, error) {
	cmd.Env = append(cmd.Env, "_LIBCONTAINER_INITTYPE="+string(initStandard))
	nsMaps := make(map[configs.NamespaceType]string)
	for _, ns := range c.config.Namespaces {
		if ns.Path != "" {
			nsMaps[ns.Type] = ns.Path
		}
	}
	_, sharePidns := nsMaps[configs.NEWPID]
	data, err := c.bootstrapData(c.config.Namespaces.CloneFlags(), nsMaps)
	if err != nil {
		return nil, err
	}
	init := &initProcess{
		cmd:             cmd,
		messageSockPair: messageSockPair,
		logFilePair:     logFilePair,
		manager:         c.cgroupManager,
		intelRdtManager: c.intelRdtManager,
		config:          c.newInitConfig(p),
		container:       c,
		process:         p,
		bootstrapData:   data,
		sharePidns:      sharePidns,
	}
	c.initProcess = init
	return init, nil
}

func (c *linuxContainer) newSetnsProcess(p *Process, cmd *exec.Cmd, messageSockPair, logFilePair filePair) (*setnsProcess, error) {
	cmd.Env = append(cmd.Env, "_LIBCONTAINER_INITTYPE="+string(initSetns))
	state, err := c.currentState()
	if err != nil {
		return nil, newSystemErrorWithCause(err, "getting container's current state")
	}
	// for setns process, we don't have to set cloneflags as the process namespaces
	// will only be set via setns syscall
	data, err := c.bootstrapData(0, state.NamespacePaths)
	if err != nil {
		return nil, err
	}
	// sysbox-runc: setns processes enter the child cgroup (i.e., the system
	// container's cgroup root); this way they can't change the cgroup resources
	// assigned to the system container itself.
	return &setnsProcess{
		cmd:             cmd,
		cgroupPaths:     c.cgroupManager.GetChildCgroupPaths(),
		rootlessCgroups: c.config.RootlessCgroups,
		intelRdtPath:    state.IntelRdtPath,
		messageSockPair: messageSockPair,
		logFilePair:     logFilePair,
		config:          c.newInitConfig(p),
		process:         p,
		bootstrapData:   data,
		initProcessPid:  state.InitProcessPid,
		container:       c,
	}, nil
}

// sysbox-runc: create a new helper process command to perform rootfs mount initialization
func (c *linuxContainer) initHelperCmdTemplate(p *Process, childInitPipe, childLogPipe *os.File) *exec.Cmd {
	cmd := exec.Command(c.initPath, c.initArgs[1:]...)
	cmd.Args[0] = c.initArgs[0]
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Dir = c.config.Rootfs
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &unix.SysProcAttr{}
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, childInitPipe)
	cmd.Env = append(cmd.Env, "GOMAXPROCS="+os.Getenv("GOMAXPROCS"))
	cmd.Env = append(cmd.Env, "_LIBCONTAINER_INITTYPE="+string(initMount))
	cmd.Env = append(cmd.Env,
		"_LIBCONTAINER_INITPIPE="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
		"_LIBCONTAINER_STATEDIR="+c.root,
	)
	cmd.ExtraFiles = append(cmd.ExtraFiles, childLogPipe)
	cmd.Env = append(cmd.Env,
		"_LIBCONTAINER_LOGPIPE="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
		"_LIBCONTAINER_LOGLEVEL="+p.LogLevel,
	)
	return cmd
}

func (c *linuxContainer) newInitConfig(process *Process) *initConfig {
	cfg := &initConfig{
		Config:           c.config,
		Args:             process.Args,
		Env:              process.Env,
		User:             process.User,
		AdditionalGroups: process.AdditionalGroups,
		Cwd:              process.Cwd,
		Capabilities:     process.Capabilities,
		PassedFilesCount: len(process.ExtraFiles),
		ContainerId:      c.ID(),
		NoNewPrivileges:  c.config.NoNewPrivileges,
		RootlessEUID:     c.config.RootlessEUID,
		RootlessCgroups:  c.config.RootlessCgroups,
		AppArmorProfile:  c.config.AppArmorProfile,
		ProcessLabel:     c.config.ProcessLabel,
		Rlimits:          c.config.Rlimits,
	}
	if process.NoNewPrivileges != nil {
		cfg.NoNewPrivileges = *process.NoNewPrivileges
	}
	if process.AppArmorProfile != "" {
		cfg.AppArmorProfile = process.AppArmorProfile
	}
	if process.Label != "" {
		cfg.ProcessLabel = process.Label
	}
	if len(process.Rlimits) > 0 {
		cfg.Rlimits = process.Rlimits
	}
	cfg.CreateConsole = process.ConsoleSocket != nil
	cfg.ConsoleWidth = process.ConsoleWidth
	cfg.ConsoleHeight = process.ConsoleHeight
	return cfg
}

func (c *linuxContainer) Destroy() error {
	var err error

	c.m.Lock()
	defer c.m.Unlock()

	// If the rootfs was chowned, revert it back to its original uid & gid
	if c.config.RootfsUidShiftType == sh.Chown {
		if c.config.RootfsCloned {
			err = c.sysMgr.RevertClonedRootfsChown()
		} else {
			err = c.revertRootfsChown()
		}
	}

	if err2 := c.state.destroy(); err == nil {
		err = err2
	}

	if c.sysFs.Enabled() {
		if err2 := c.sysFs.Unregister(); err == nil {
			err = err2
		}
	}

	if c.sysMgr.Enabled() {
		if err2 := c.sysMgr.Unregister(); err == nil {
			err = err2
		}
	} else {
		// If sysbox-mgr is not present (i.e., unit testing), then we teardown
		// shiftfs marks here.
		mounts, err := mount.GetMounts()
		if err != nil {
			return fmt.Errorf("failed to read mountinfo: %s", err)
		}

		if err2 := c.teardownShiftfsMarkLocal(mounts); err == nil {
			err = err2
		}
	}

	return err
}

func (c *linuxContainer) Pause() error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	switch status {
	case Running, Created:
		if err := c.cgroupManager.Freeze(configs.Frozen); err != nil {
			return err
		}

		if c.config.RootfsUidShiftType == sh.Chown {
			if c.config.RootfsCloned {
				if err := c.sysMgr.RevertClonedRootfsChown(); err != nil {
					return err
				}
			} else {
				if err := c.revertRootfsChown(); err == nil {
					return err
				}
			}
		}

		if c.sysMgr.Enabled() {
			if err := c.sysMgr.Pause(); err != nil {
				return err
			}
		}
		return c.state.transition(&pausedState{
			c: c,
		})
	}
	return newGenericError(fmt.Errorf("container not running or created: %s", status), ContainerNotRunning)
}

func (c *linuxContainer) Resume() error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	if status != Paused {
		return newGenericError(fmt.Errorf("container not paused"), ContainerNotPaused)
	}

	if c.config.RootfsUidShiftType == sh.Chown {
		if c.config.RootfsCloned {
			uidOffset := int32(c.config.UidMappings[0].HostID)
			gidOffset := int32(c.config.GidMappings[0].HostID)

			if err := c.sysMgr.ChownClonedRootfs(uidOffset, gidOffset); err != nil {
				return err
			}
		} else {
			if err := c.chownRootfs(); err != nil {
				return err
			}
		}
	}

	if err := c.cgroupManager.Freeze(configs.Thawed); err != nil {
		return err
	}
	return c.state.transition(&runningState{
		c: c,
	})
}

func (c *linuxContainer) NotifyOOM() (<-chan struct{}, error) {
	// XXX(cyphar): This requires cgroups.
	if c.config.RootlessCgroups {
		logrus.Warn("getting OOM notifications may fail if you don't have the full access to cgroups")
	}
	path := c.cgroupManager.Path("memory")
	if cgroups.IsCgroup2UnifiedMode() {
		return notifyOnOOMV2(path)
	}
	return notifyOnOOM(path)
}

func (c *linuxContainer) NotifyMemoryPressure(level PressureLevel) (<-chan struct{}, error) {
	// XXX(cyphar): This requires cgroups.
	if c.config.RootlessCgroups {
		logrus.Warn("getting memory pressure notifications may fail if you don't have the full access to cgroups")
	}
	return notifyMemoryPressure(c.cgroupManager.Path("memory"), level)
}

var criuFeatures *criurpc.CriuFeatures

func (c *linuxContainer) checkCriuFeatures(criuOpts *CriuOpts, rpcOpts *criurpc.CriuOpts, criuFeat *criurpc.CriuFeatures) error {

	t := criurpc.CriuReqType_FEATURE_CHECK

	// make sure the features we are looking for are really not from
	// some previous check
	criuFeatures = nil

	req := &criurpc.CriuReq{
		Type: &t,
		// Theoretically this should not be necessary but CRIU
		// segfaults if Opts is empty.
		// Fixed in CRIU  2.12
		Opts:     rpcOpts,
		Features: criuFeat,
	}

	err := c.criuSwrk(nil, req, criuOpts, nil)
	if err != nil {
		logrus.Debugf("%s", err)
		return errors.New("CRIU feature check failed")
	}

	logrus.Debugf("Feature check says: %s", criuFeatures)
	missingFeatures := false

	// The outer if checks if the fields actually exist
	if (criuFeat.MemTrack != nil) &&
		(criuFeatures.MemTrack != nil) {
		// The inner if checks if they are set to true
		if *criuFeat.MemTrack && !*criuFeatures.MemTrack {
			missingFeatures = true
			logrus.Debugf("CRIU does not support MemTrack")
		}
	}

	// This needs to be repeated for every new feature check.
	// Is there a way to put this in a function. Reflection?
	if (criuFeat.LazyPages != nil) &&
		(criuFeatures.LazyPages != nil) {
		if *criuFeat.LazyPages && !*criuFeatures.LazyPages {
			missingFeatures = true
			logrus.Debugf("CRIU does not support LazyPages")
		}
	}

	if missingFeatures {
		return errors.New("CRIU is missing features")
	}

	return nil
}

func compareCriuVersion(criuVersion int, minVersion int) error {
	// simple function to perform the actual version compare
	if criuVersion < minVersion {
		return fmt.Errorf("CRIU version %d must be %d or higher", criuVersion, minVersion)
	}

	return nil
}

// checkCriuVersion checks Criu version greater than or equal to minVersion
func (c *linuxContainer) checkCriuVersion(minVersion int) error {

	// If the version of criu has already been determined there is no need
	// to ask criu for the version again. Use the value from c.criuVersion.
	if c.criuVersion != 0 {
		return compareCriuVersion(c.criuVersion, minVersion)
	}

	criu := criu.MakeCriu()
	criu.SetCriuPath(c.criuPath)
	var err error
	c.criuVersion, err = criu.GetCriuVersion()
	if err != nil {
		return fmt.Errorf("CRIU version check failed: %s", err)
	}

	return compareCriuVersion(c.criuVersion, minVersion)
}

const descriptorsFilename = "descriptors.json"

func (c *linuxContainer) addCriuDumpMount(req *criurpc.CriuReq, m *configs.Mount) {
	mountDest := strings.TrimPrefix(m.Destination, c.config.Rootfs)
	extMnt := &criurpc.ExtMountMap{
		Key: proto.String(mountDest),
		Val: proto.String(mountDest),
	}
	req.Opts.ExtMnt = append(req.Opts.ExtMnt, extMnt)
}

func (c *linuxContainer) addMaskPaths(req *criurpc.CriuReq) error {
	for _, path := range c.config.MaskPaths {
		fi, err := os.Stat(fmt.Sprintf("/proc/%d/root/%s", c.initProcess.pid(), path))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if fi.IsDir() {
			continue
		}

		extMnt := &criurpc.ExtMountMap{
			Key: proto.String(path),
			Val: proto.String("/dev/null"),
		}
		req.Opts.ExtMnt = append(req.Opts.ExtMnt, extMnt)
	}
	return nil
}

func (c *linuxContainer) handleCriuConfigurationFile(rpcOpts *criurpc.CriuOpts) {
	// CRIU will evaluate a configuration starting with release 3.11.
	// Settings in the configuration file will overwrite RPC settings.
	// Look for annotations. The annotation 'org.criu.config'
	// specifies if CRIU should use a different, container specific
	// configuration file.
	_, annotations := utils.Annotations(c.config.Labels)
	configFile, exists := annotations["org.criu.config"]
	if exists {
		// If the annotation 'org.criu.config' exists and is set
		// to a non-empty string, tell CRIU to use that as a
		// configuration file. If the file does not exist, CRIU
		// will just ignore it.
		if configFile != "" {
			rpcOpts.ConfigFile = proto.String(configFile)
		}
		// If 'org.criu.config' exists and is set to an empty
		// string, a runc specific CRIU configuration file will
		// be not set at all.
	} else {
		// If the mentioned annotation has not been found, specify
		// a default CRIU configuration file.
		rpcOpts.ConfigFile = proto.String("/etc/criu/runc.conf")
	}
}

func (c *linuxContainer) criuSupportsExtNS(t configs.NamespaceType) bool {
	var minVersion int
	switch t {
	case configs.NEWNET:
		// CRIU supports different external namespace with different released CRIU versions.
		// For network namespaces to work we need at least criu 3.11.0 => 31100.
		minVersion = 31100
	case configs.NEWPID:
		// For PID namespaces criu 31500 is needed.
		minVersion = 31500
	default:
		return false
	}
	return c.checkCriuVersion(minVersion) == nil
}

func criuNsToKey(t configs.NamespaceType) string {
	return "extRoot" + strings.Title(configs.NsName(t)) + "NS"
}

func (c *linuxContainer) handleCheckpointingExternalNamespaces(rpcOpts *criurpc.CriuOpts, t configs.NamespaceType) error {
	if !c.criuSupportsExtNS(t) {
		return nil
	}

	nsPath := c.config.Namespaces.PathOf(t)
	if nsPath == "" {
		return nil
	}
	// CRIU expects the information about an external namespace
	// like this: --external <TYPE>[<inode>]:<key>
	// This <key> is always 'extRoot<TYPE>NS'.
	var ns unix.Stat_t
	if err := unix.Stat(nsPath, &ns); err != nil {
		return err
	}
	criuExternal := fmt.Sprintf("%s[%d]:%s", configs.NsName(t), ns.Ino, criuNsToKey(t))
	rpcOpts.External = append(rpcOpts.External, criuExternal)

	return nil
}

func (c *linuxContainer) handleRestoringNamespaces(rpcOpts *criurpc.CriuOpts, extraFiles *[]*os.File) error {
	for _, ns := range c.config.Namespaces {
		switch ns.Type {
		case configs.NEWNET, configs.NEWPID:
			// If the container is running in a network or PID namespace and has
			// a path to the network or PID namespace configured, we will dump
			// that network or PID namespace as an external namespace and we
			// will expect that the namespace exists during restore.
			// This basically means that CRIU will ignore the namespace
			// and expect it to be setup correctly.
			if err := c.handleRestoringExternalNamespaces(rpcOpts, extraFiles, ns.Type); err != nil {
				return err
			}
		default:
			// For all other namespaces except NET and PID CRIU has
			// a simpler way of joining the existing namespace if set
			nsPath := c.config.Namespaces.PathOf(ns.Type)
			if nsPath == "" {
				continue
			}
			if ns.Type == configs.NEWCGROUP {
				// CRIU has no code to handle NEWCGROUP
				return fmt.Errorf("Do not know how to handle namespace %v", ns.Type)
			}
			// CRIU has code to handle NEWTIME, but it does not seem to be defined in runc

			// CRIU will issue a warning for NEWUSER:
			// criu/namespaces.c: 'join-ns with user-namespace is not fully tested and dangerous'
			rpcOpts.JoinNs = append(rpcOpts.JoinNs, &criurpc.JoinNamespace{
				Ns:     proto.String(configs.NsName(ns.Type)),
				NsFile: proto.String(nsPath),
			})
		}
	}

	return nil
}

func (c *linuxContainer) handleRestoringExternalNamespaces(rpcOpts *criurpc.CriuOpts, extraFiles *[]*os.File, t configs.NamespaceType) error {
	if !c.criuSupportsExtNS(t) {
		return nil
	}

	nsPath := c.config.Namespaces.PathOf(t)
	if nsPath == "" {
		return nil
	}
	// CRIU wants the information about an existing namespace
	// like this: --inherit-fd fd[<fd>]:<key>
	// The <key> needs to be the same as during checkpointing.
	// We are always using 'extRoot<TYPE>NS' as the key in this.
	nsFd, err := os.Open(nsPath)
	if err != nil {
		logrus.Errorf("If a specific network namespace is defined it must exist: %s", err)
		return fmt.Errorf("Requested network namespace %v does not exist", nsPath)
	}
	inheritFd := &criurpc.InheritFd{
		Key: proto.String(criuNsToKey(t)),
		// The offset of four is necessary because 0, 1, 2 and 3 are
		// already used by stdin, stdout, stderr, 'criu swrk' socket.
		Fd: proto.Int32(int32(4 + len(*extraFiles))),
	}
	rpcOpts.InheritFd = append(rpcOpts.InheritFd, inheritFd)
	// All open FDs need to be transferred to CRIU via extraFiles
	*extraFiles = append(*extraFiles, nsFd)

	return nil
}

func (c *linuxContainer) Checkpoint(criuOpts *CriuOpts) error {
	c.m.Lock()
	defer c.m.Unlock()

	// Checkpoint is unlikely to work if os.Geteuid() != 0 || system.RunningInUserNS().
	// (CLI prints a warning)
	// TODO(avagin): Figure out how to make this work nicely. CRIU 2.0 has
	//               support for doing unprivileged dumps, but the setup of
	//               rootless containers might make this complicated.

	// We are relying on the CRIU version RPC which was introduced with CRIU 3.0.0
	if err := c.checkCriuVersion(30000); err != nil {
		return err
	}

	if criuOpts.ImagesDirectory == "" {
		return errors.New("invalid directory to save checkpoint")
	}

	// Since a container can be C/R'ed multiple times,
	// the checkpoint directory may already exist.
	if err := os.Mkdir(criuOpts.ImagesDirectory, 0700); err != nil && !os.IsExist(err) {
		return err
	}

	if criuOpts.WorkDirectory == "" {
		criuOpts.WorkDirectory = filepath.Join(c.root, "criu.work")
	}

	if err := os.Mkdir(criuOpts.WorkDirectory, 0700); err != nil && !os.IsExist(err) {
		return err
	}

	workDir, err := os.Open(criuOpts.WorkDirectory)
	if err != nil {
		return err
	}
	defer workDir.Close()

	imageDir, err := os.Open(criuOpts.ImagesDirectory)
	if err != nil {
		return err
	}
	defer imageDir.Close()

	rpcOpts := criurpc.CriuOpts{
		ImagesDirFd:     proto.Int32(int32(imageDir.Fd())),
		WorkDirFd:       proto.Int32(int32(workDir.Fd())),
		LogLevel:        proto.Int32(4),
		LogFile:         proto.String("dump.log"),
		Root:            proto.String(c.config.Rootfs),
		ManageCgroups:   proto.Bool(true),
		NotifyScripts:   proto.Bool(true),
		Pid:             proto.Int32(int32(c.initProcess.pid())),
		ShellJob:        proto.Bool(criuOpts.ShellJob),
		LeaveRunning:    proto.Bool(criuOpts.LeaveRunning),
		TcpEstablished:  proto.Bool(criuOpts.TcpEstablished),
		ExtUnixSk:       proto.Bool(criuOpts.ExternalUnixConnections),
		FileLocks:       proto.Bool(criuOpts.FileLocks),
		EmptyNs:         proto.Uint32(criuOpts.EmptyNs),
		OrphanPtsMaster: proto.Bool(true),
		AutoDedup:       proto.Bool(criuOpts.AutoDedup),
		LazyPages:       proto.Bool(criuOpts.LazyPages),
	}

	c.handleCriuConfigurationFile(&rpcOpts)

	// If the container is running in a network namespace and has
	// a path to the network namespace configured, we will dump
	// that network namespace as an external namespace and we
	// will expect that the namespace exists during restore.
	// This basically means that CRIU will ignore the namespace
	// and expect to be setup correctly.
	if err := c.handleCheckpointingExternalNamespaces(&rpcOpts, configs.NEWNET); err != nil {
		return err
	}

	// Same for possible external PID namespaces
	if err := c.handleCheckpointingExternalNamespaces(&rpcOpts, configs.NEWPID); err != nil {
		return err
	}

	// CRIU can use cgroup freezer; when rpcOpts.FreezeCgroup
	// is not set, CRIU uses ptrace() to pause the processes.
	// Note cgroup v2 freezer is only supported since CRIU release 3.14.
	if !cgroups.IsCgroup2UnifiedMode() || c.checkCriuVersion(31400) == nil {
		if fcg := c.cgroupManager.Path("freezer"); fcg != "" {
			rpcOpts.FreezeCgroup = proto.String(fcg)
		}
	}

	// append optional criu opts, e.g., page-server and port
	if criuOpts.PageServer.Address != "" && criuOpts.PageServer.Port != 0 {
		rpcOpts.Ps = &criurpc.CriuPageServerInfo{
			Address: proto.String(criuOpts.PageServer.Address),
			Port:    proto.Int32(criuOpts.PageServer.Port),
		}
	}

	//pre-dump may need parentImage param to complete iterative migration
	if criuOpts.ParentImage != "" {
		rpcOpts.ParentImg = proto.String(criuOpts.ParentImage)
		rpcOpts.TrackMem = proto.Bool(true)
	}

	// append optional manage cgroups mode
	if criuOpts.ManageCgroupsMode != 0 {
		mode := criurpc.CriuCgMode(criuOpts.ManageCgroupsMode)
		rpcOpts.ManageCgroupsMode = &mode
	}

	var t criurpc.CriuReqType
	if criuOpts.PreDump {
		feat := criurpc.CriuFeatures{
			MemTrack: proto.Bool(true),
		}

		if err := c.checkCriuFeatures(criuOpts, &rpcOpts, &feat); err != nil {
			return err
		}

		t = criurpc.CriuReqType_PRE_DUMP
	} else {
		t = criurpc.CriuReqType_DUMP
	}

	if criuOpts.LazyPages {
		// lazy migration requested; check if criu supports it
		feat := criurpc.CriuFeatures{
			LazyPages: proto.Bool(true),
		}
		if err := c.checkCriuFeatures(criuOpts, &rpcOpts, &feat); err != nil {
			return err
		}

		if fd := criuOpts.StatusFd; fd != -1 {
			// check that the FD is valid
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
			if err != nil {
				return fmt.Errorf("invalid --status-fd argument %d: %w", fd, err)
			}
			// and writable
			if flags&unix.O_WRONLY == 0 {
				return fmt.Errorf("invalid --status-fd argument %d: not writable", fd)
			}

			if c.checkCriuVersion(31500) != nil {
				// For criu 3.15+, use notifications (see case "status-ready"
				// in criuNotifications). Otherwise, rely on criu status fd.
				rpcOpts.StatusFd = proto.Int32(int32(fd))
			}
		}
	}

	req := &criurpc.CriuReq{
		Type: &t,
		Opts: &rpcOpts,
	}

	// no need to dump all this in pre-dump
	if !criuOpts.PreDump {
		hasCgroupns := c.config.Namespaces.Contains(configs.NEWCGROUP)
		for _, m := range c.config.Mounts {
			switch m.Device {
			case "bind":
				c.addCriuDumpMount(req, m)
			case "cgroup":
				if cgroups.IsCgroup2UnifiedMode() || hasCgroupns {
					// real mount(s)
					continue
				}
				// a set of "external" bind mounts
				binds, err := getCgroupMounts(m)
				if err != nil {
					return err
				}
				for _, b := range binds {
					c.addCriuDumpMount(req, b)
				}
			}
		}

		if err := c.addMaskPaths(req); err != nil {
			return err
		}

		for _, node := range c.config.Devices {
			m := &configs.Mount{Destination: node.Path, Source: node.Path}
			c.addCriuDumpMount(req, m)
		}

		// Write the FD info to a file in the image directory
		fdsJSON, err := json.Marshal(c.initProcess.externalDescriptors())
		if err != nil {
			return err
		}

		err = ioutil.WriteFile(filepath.Join(criuOpts.ImagesDirectory, descriptorsFilename), fdsJSON, 0600)
		if err != nil {
			return err
		}
	}

	err = c.criuSwrk(nil, req, criuOpts, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *linuxContainer) addCriuRestoreMount(req *criurpc.CriuReq, m *configs.Mount) {
	mountDest := strings.TrimPrefix(m.Destination, c.config.Rootfs)
	extMnt := &criurpc.ExtMountMap{
		Key: proto.String(mountDest),
		Val: proto.String(m.Source),
	}
	req.Opts.ExtMnt = append(req.Opts.ExtMnt, extMnt)
}

func (c *linuxContainer) restoreNetwork(req *criurpc.CriuReq, criuOpts *CriuOpts) {
	for _, iface := range c.config.Networks {
		switch iface.Type {
		case "veth":
			veth := new(criurpc.CriuVethPair)
			veth.IfOut = proto.String(iface.HostInterfaceName)
			veth.IfIn = proto.String(iface.Name)
			req.Opts.Veths = append(req.Opts.Veths, veth)
		case "loopback":
			// Do nothing
		}
	}
	for _, i := range criuOpts.VethPairs {
		veth := new(criurpc.CriuVethPair)
		veth.IfOut = proto.String(i.HostInterfaceName)
		veth.IfIn = proto.String(i.ContainerInterfaceName)
		req.Opts.Veths = append(req.Opts.Veths, veth)
	}
}

// makeCriuRestoreMountpoints makes the actual mountpoints for the
// restore using CRIU. This function is inspired from the code in
// rootfs_linux.go
func (c *linuxContainer) makeCriuRestoreMountpoints(m *configs.Mount) error {
	switch m.Device {
	case "cgroup":
		// No mount point(s) need to be created:
		//
		// * for v1, mount points are saved by CRIU because
		//   /sys/fs/cgroup is a tmpfs mount
		//
		// * for v2, /sys/fs/cgroup is a real mount, but
		//   the mountpoint appears as soon as /sys is mounted
		return nil
	case "bind":
		// The prepareBindDest() function checks if source
		// exists. So it cannot be used for other filesystem types.
		//
		// sysbox-runc: this is no longer the case; prepareBindDest() only checks the
		// mount destination; if we need to check the mount source we need to create a
		// function that explicitly does this.
		if err := prepareBindDest(m, true, c.config, nil); err != nil {
			return err
		}
	default:
		// for all other filesystems just create the mountpoints
		dest, err := securejoin.SecureJoin(c.config.Rootfs, m.Destination)
		if err != nil {
			return err
		}
		m.Destination = dest
		if err := os.MkdirAll(dest, 0755); err != nil {
			return err
		}
	}
	return nil
}

// isPathInPrefixList is a small function for CRIU restore to make sure
// mountpoints, which are on a tmpfs, are not created in the roofs
func isPathInPrefixList(path string, prefix []string) bool {
	for _, p := range prefix {
		if strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// prepareCriuRestoreMounts tries to set up the rootfs of the
// container to be restored in the same way runc does it for
// initial container creation. Even for a read-only rootfs container
// runc modifies the rootfs to add mountpoints which do not exist.
// This function also creates missing mountpoints as long as they
// are not on top of a tmpfs, as CRIU will restore tmpfs content anyway.
func (c *linuxContainer) prepareCriuRestoreMounts(mounts []*configs.Mount) error {
	// First get a list of a all tmpfs mounts
	tmpfs := []string{}
	for _, m := range mounts {
		switch m.Device {
		case "tmpfs":
			tmpfs = append(tmpfs, m.Destination)
		}
	}
	// Now go through all mounts and create the mountpoints
	// if the mountpoints are not on a tmpfs, as CRIU will
	// restore the complete tmpfs content from its checkpoint.
	for _, m := range mounts {
		if !isPathInPrefixList(m.Destination, tmpfs) {
			if err := c.makeCriuRestoreMountpoints(m); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *linuxContainer) Restore(process *Process, criuOpts *CriuOpts) error {
	c.m.Lock()
	defer c.m.Unlock()

	var extraFiles []*os.File

	// Restore is unlikely to work if os.Geteuid() != 0 || system.RunningInUserNS().
	// (CLI prints a warning)
	// TODO(avagin): Figure out how to make this work nicely. CRIU doesn't have
	//               support for unprivileged restore at the moment.

	// We are relying on the CRIU version RPC which was introduced with CRIU 3.0.0
	if err := c.checkCriuVersion(30000); err != nil {
		return err
	}
	if criuOpts.WorkDirectory == "" {
		criuOpts.WorkDirectory = filepath.Join(c.root, "criu.work")
	}
	// Since a container can be C/R'ed multiple times,
	// the work directory may already exist.
	if err := os.Mkdir(criuOpts.WorkDirectory, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	workDir, err := os.Open(criuOpts.WorkDirectory)
	if err != nil {
		return err
	}
	defer workDir.Close()
	if criuOpts.ImagesDirectory == "" {
		return errors.New("invalid directory to restore checkpoint")
	}
	imageDir, err := os.Open(criuOpts.ImagesDirectory)
	if err != nil {
		return err
	}
	defer imageDir.Close()
	// CRIU has a few requirements for a root directory:
	// * it must be a mount point
	// * its parent must not be overmounted
	// c.config.Rootfs is bind-mounted to a temporary directory
	// to satisfy these requirements.
	root := filepath.Join(c.root, "criu-root")
	if err := os.Mkdir(root, 0755); err != nil {
		return err
	}
	defer os.Remove(root)
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	err = unix.Mount(c.config.Rootfs, root, "", unix.MS_BIND|unix.MS_REC, "")
	if err != nil {
		return err
	}
	defer unix.Unmount(root, unix.MNT_DETACH)
	t := criurpc.CriuReqType_RESTORE
	req := &criurpc.CriuReq{
		Type: &t,
		Opts: &criurpc.CriuOpts{
			ImagesDirFd:     proto.Int32(int32(imageDir.Fd())),
			WorkDirFd:       proto.Int32(int32(workDir.Fd())),
			EvasiveDevices:  proto.Bool(true),
			LogLevel:        proto.Int32(4),
			LogFile:         proto.String("restore.log"),
			RstSibling:      proto.Bool(true),
			Root:            proto.String(root),
			ManageCgroups:   proto.Bool(true),
			NotifyScripts:   proto.Bool(true),
			ShellJob:        proto.Bool(criuOpts.ShellJob),
			ExtUnixSk:       proto.Bool(criuOpts.ExternalUnixConnections),
			TcpEstablished:  proto.Bool(criuOpts.TcpEstablished),
			FileLocks:       proto.Bool(criuOpts.FileLocks),
			EmptyNs:         proto.Uint32(criuOpts.EmptyNs),
			OrphanPtsMaster: proto.Bool(true),
			AutoDedup:       proto.Bool(criuOpts.AutoDedup),
			LazyPages:       proto.Bool(criuOpts.LazyPages),
		},
	}

	c.handleCriuConfigurationFile(req.Opts)

	if err := c.handleRestoringNamespaces(req.Opts, &extraFiles); err != nil {
		return err
	}

	// This will modify the rootfs of the container in the same way runc
	// modifies the container during initial creation.
	if err := c.prepareCriuRestoreMounts(c.config.Mounts); err != nil {
		return err
	}

	hasCgroupns := c.config.Namespaces.Contains(configs.NEWCGROUP)
	for _, m := range c.config.Mounts {
		switch m.Device {
		case "bind":
			c.addCriuRestoreMount(req, m)
		case "cgroup":
			if cgroups.IsCgroup2UnifiedMode() || hasCgroupns {
				continue
			}
			// cgroup v1 is a set of bind mounts, unless cgroupns is used
			binds, err := getCgroupMounts(m)
			if err != nil {
				return err
			}
			for _, b := range binds {
				c.addCriuRestoreMount(req, b)
			}
		}
	}

	if len(c.config.MaskPaths) > 0 {
		m := &configs.Mount{Destination: "/dev/null", Source: "/dev/null"}
		c.addCriuRestoreMount(req, m)
	}

	for _, node := range c.config.Devices {
		m := &configs.Mount{Destination: node.Path, Source: node.Path}
		c.addCriuRestoreMount(req, m)
	}

	if criuOpts.EmptyNs&unix.CLONE_NEWNET == 0 {
		c.restoreNetwork(req, criuOpts)
	}

	// append optional manage cgroups mode
	if criuOpts.ManageCgroupsMode != 0 {
		mode := criurpc.CriuCgMode(criuOpts.ManageCgroupsMode)
		req.Opts.ManageCgroupsMode = &mode
	}

	var (
		fds    []string
		fdJSON []byte
	)
	if fdJSON, err = ioutil.ReadFile(filepath.Join(criuOpts.ImagesDirectory, descriptorsFilename)); err != nil {
		return err
	}

	if err := json.Unmarshal(fdJSON, &fds); err != nil {
		return err
	}
	for i := range fds {
		if s := fds[i]; strings.Contains(s, "pipe:") {
			inheritFd := new(criurpc.InheritFd)
			inheritFd.Key = proto.String(s)
			inheritFd.Fd = proto.Int32(int32(i))
			req.Opts.InheritFd = append(req.Opts.InheritFd, inheritFd)
		}
	}
	err = c.criuSwrk(process, req, criuOpts, extraFiles)

	// Now that CRIU is done let's close all opened FDs CRIU needed.
	for _, fd := range extraFiles {
		fd.Close()
	}

	return err
}

func (c *linuxContainer) criuApplyCgroups(pid int, req *criurpc.CriuReq) error {
	// need to apply cgroups only on restore
	if req.GetType() != criurpc.CriuReqType_RESTORE {
		return nil
	}

	// XXX: Do we need to deal with this case? AFAIK criu still requires root.
	if err := c.cgroupManager.Apply(pid); err != nil {
		return err
	}
	// sysbox-runc: place the pid in the sys container's cgroup root. The prior call to
	// Apply(pid) is necessary because Apply() populates the cgroup manager's internal
	// state.
	if err := c.cgroupManager.ApplyChildCgroup(pid); err != nil {
		return err
	}

	if err := c.cgroupManager.Set(c.config); err != nil {
		return newSystemError(err)
	}

	if cgroups.IsCgroup2UnifiedMode() {
		return nil
	}

	// the stuff below is cgroupv1-specific
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	cgroupsPaths, err := cgroups.ParseCgroupFile(path)
	if err != nil {
		return err
	}

	for c, p := range cgroupsPaths {
		cgroupRoot := &criurpc.CgroupRoot{
			Ctrl: proto.String(c),
			Path: proto.String(p),
		}
		req.Opts.CgRoot = append(req.Opts.CgRoot, cgroupRoot)
	}

	return nil
}

func (c *linuxContainer) criuSwrk(process *Process, req *criurpc.CriuReq, opts *CriuOpts, extraFiles []*os.File) error {
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}

	var logPath string
	if opts != nil {
		logPath = filepath.Join(opts.WorkDirectory, req.GetOpts().GetLogFile())
	} else {
		// For the VERSION RPC 'opts' is set to 'nil' and therefore
		// opts.WorkDirectory does not exist. Set logPath to "".
		logPath = ""
	}
	criuClient := os.NewFile(uintptr(fds[0]), "criu-transport-client")
	criuClientFileCon, err := net.FileConn(criuClient)
	criuClient.Close()
	if err != nil {
		return err
	}

	criuClientCon := criuClientFileCon.(*net.UnixConn)
	defer criuClientCon.Close()

	criuServer := os.NewFile(uintptr(fds[1]), "criu-transport-server")
	defer criuServer.Close()

	args := []string{"swrk", "3"}
	if c.criuVersion != 0 {
		// If the CRIU Version is still '0' then this is probably
		// the initial CRIU run to detect the version. Skip it.
		logrus.Debugf("Using CRIU %d at: %s", c.criuVersion, c.criuPath)
	}
	logrus.Debugf("Using CRIU with following args: %s", args)
	cmd := exec.Command(c.criuPath, args...)
	if process != nil {
		cmd.Stdin = process.Stdin
		cmd.Stdout = process.Stdout
		cmd.Stderr = process.Stderr
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, criuServer)
	if extraFiles != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, extraFiles...)
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	// we close criuServer so that even if CRIU crashes or unexpectedly exits, runc will not hang.
	criuServer.Close()
	// cmd.Process will be replaced by a restored init.
	criuProcess := cmd.Process

	var criuProcessState *os.ProcessState
	defer func() {
		if criuProcessState == nil {
			criuClientCon.Close()
			_, err := criuProcess.Wait()
			if err != nil {
				logrus.Warnf("wait on criuProcess returned %v", err)
			}
		}
	}()

	if err := c.criuApplyCgroups(criuProcess.Pid, req); err != nil {
		return err
	}

	var extFds []string
	if process != nil {
		extFds, err = getPipeFds(criuProcess.Pid)
		if err != nil {
			return err
		}
	}

	logrus.Debugf("Using CRIU in %s mode", req.GetType().String())
	// In the case of criurpc.CriuReqType_FEATURE_CHECK req.GetOpts()
	// should be empty. For older CRIU versions it still will be
	// available but empty. criurpc.CriuReqType_VERSION actually
	// has no req.GetOpts().
	if !(req.GetType() == criurpc.CriuReqType_FEATURE_CHECK ||
		req.GetType() == criurpc.CriuReqType_VERSION) {

		val := reflect.ValueOf(req.GetOpts())
		v := reflect.Indirect(val)
		for i := 0; i < v.NumField(); i++ {
			st := v.Type()
			name := st.Field(i).Name
			if strings.HasPrefix(name, "XXX_") {
				continue
			}
			value := val.MethodByName("Get" + name).Call([]reflect.Value{})
			logrus.Debugf("CRIU option %s with value %v", name, value[0])
		}
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	_, err = criuClientCon.Write(data)
	if err != nil {
		return err
	}

	buf := make([]byte, 10*4096)
	oob := make([]byte, 4096)
	for {
		n, oobn, _, _, err := criuClientCon.ReadMsgUnix(buf, oob)
		if req.Opts != nil && req.Opts.StatusFd != nil {
			// Close status_fd as soon as we got something back from criu,
			// assuming it has consumed (reopened) it by this time.
			// Otherwise it will might be left open forever and whoever
			// is waiting on it will wait forever.
			fd := int(*req.Opts.StatusFd)
			_ = unix.Close(fd)
			req.Opts.StatusFd = nil
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("unexpected EOF")
		}
		if n == len(buf) {
			return errors.New("buffer is too small")
		}

		resp := new(criurpc.CriuResp)
		err = proto.Unmarshal(buf[:n], resp)
		if err != nil {
			return err
		}
		if !resp.GetSuccess() {
			typeString := req.GetType().String()
			return fmt.Errorf("criu failed: type %s errno %d\nlog file: %s", typeString, resp.GetCrErrno(), logPath)
		}

		t := resp.GetType()
		switch {
		case t == criurpc.CriuReqType_FEATURE_CHECK:
			logrus.Debugf("Feature check says: %s", resp)
			criuFeatures = resp.GetFeatures()
		case t == criurpc.CriuReqType_NOTIFY:
			if err := c.criuNotifications(resp, process, cmd, opts, extFds, oob[:oobn]); err != nil {
				return err
			}
			t = criurpc.CriuReqType_NOTIFY
			req = &criurpc.CriuReq{
				Type:          &t,
				NotifySuccess: proto.Bool(true),
			}
			data, err = proto.Marshal(req)
			if err != nil {
				return err
			}
			_, err = criuClientCon.Write(data)
			if err != nil {
				return err
			}
			continue
		case t == criurpc.CriuReqType_RESTORE:
		case t == criurpc.CriuReqType_DUMP:
		case t == criurpc.CriuReqType_PRE_DUMP:
		default:
			return fmt.Errorf("unable to parse the response %s", resp.String())
		}

		break
	}

	criuClientCon.CloseWrite()
	// cmd.Wait() waits cmd.goroutines which are used for proxying file descriptors.
	// Here we want to wait only the CRIU process.
	criuProcessState, err = criuProcess.Wait()
	if err != nil {
		return err
	}

	// In pre-dump mode CRIU is in a loop and waits for
	// the final DUMP command.
	// The current runc pre-dump approach, however, is
	// start criu in PRE_DUMP once for a single pre-dump
	// and not the whole series of pre-dump, pre-dump, ...m, dump
	// If we got the message CriuReqType_PRE_DUMP it means
	// CRIU was successful and we need to forcefully stop CRIU
	if !criuProcessState.Success() && *req.Type != criurpc.CriuReqType_PRE_DUMP {
		return fmt.Errorf("criu failed: %s\nlog file: %s", criuProcessState.String(), logPath)
	}
	return nil
}

// block any external network activity
func lockNetwork(config *configs.Config) error {
	for _, config := range config.Networks {
		strategy, err := getStrategy(config.Type)
		if err != nil {
			return err
		}

		if err := strategy.detach(config); err != nil {
			return err
		}
	}
	return nil
}

func unlockNetwork(config *configs.Config) error {
	for _, config := range config.Networks {
		strategy, err := getStrategy(config.Type)
		if err != nil {
			return err
		}
		if err = strategy.attach(config); err != nil {
			return err
		}
	}
	return nil
}

func (c *linuxContainer) criuNotifications(resp *criurpc.CriuResp, process *Process, cmd *exec.Cmd, opts *CriuOpts, fds []string, oob []byte) error {
	notify := resp.GetNotify()
	if notify == nil {
		return fmt.Errorf("invalid response: %s", resp.String())
	}
	script := notify.GetScript()
	logrus.Debugf("notify: %s\n", script)
	switch script {
	case "post-dump":
		f, err := os.Create(filepath.Join(c.root, "checkpoint"))
		if err != nil {
			return err
		}
		f.Close()
	case "network-unlock":
		if err := unlockNetwork(c.config); err != nil {
			return err
		}
	case "network-lock":
		if err := lockNetwork(c.config); err != nil {
			return err
		}
	case "setup-namespaces":
		if c.config.Hooks != nil {
			s, err := c.currentOCIState()
			if err != nil {
				return nil
			}
			s.Pid = int(notify.GetPid())

			if err := c.config.Hooks[configs.Prestart].RunHooks(s); err != nil {
				return err
			}
			if err := c.config.Hooks[configs.CreateRuntime].RunHooks(s); err != nil {
				return err
			}
		}
	case "post-restore":
		pid := notify.GetPid()

		p, err := os.FindProcess(int(pid))
		if err != nil {
			return err
		}
		cmd.Process = p

		r, err := newRestoredProcess(cmd, fds)
		if err != nil {
			return err
		}
		process.ops = r
		if err := c.state.transition(&restoredState{
			imageDir: opts.ImagesDirectory,
			c:        c,
		}); err != nil {
			return err
		}
		// create a timestamp indicating when the restored checkpoint was started
		c.created = time.Now().UTC()
		if _, err := c.updateState(r); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(c.root, "checkpoint")); err != nil {
			if !os.IsNotExist(err) {
				logrus.Error(err)
			}
		}
	case "orphan-pts-master":
		scm, err := unix.ParseSocketControlMessage(oob)
		if err != nil {
			return err
		}
		fds, err := unix.ParseUnixRights(&scm[0])
		if err != nil {
			return err
		}

		master := os.NewFile(uintptr(fds[0]), "orphan-pts-master")
		defer master.Close()

		// While we can access console.master, using the API is a good idea.
		if err := utils.SendFd(process.ConsoleSocket, master.Name(), master.Fd()); err != nil {
			return err
		}
	case "status-ready":
		if opts.StatusFd != -1 {
			// write \0 to status fd to notify that lazy page server is ready
			_, err := unix.Write(opts.StatusFd, []byte{0})
			if err != nil {
				logrus.Warnf("can't write \\0 to status fd: %v", err)
			}
			_ = unix.Close(opts.StatusFd)
			opts.StatusFd = -1
		}
	}
	return nil
}

func (c *linuxContainer) updateState(process parentProcess) (*State, error) {
	if process != nil {
		c.initProcess = process
	}
	state, err := c.currentState()
	if err != nil {
		return nil, err
	}
	err = c.saveState(state)
	if err != nil {
		return nil, err
	}
	return state, nil
}

func (c *linuxContainer) saveState(s *State) (retErr error) {
	tmpFile, err := ioutil.TempFile(c.root, "state-")
	if err != nil {
		return err
	}

	defer func() {
		if retErr != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
		}
	}()

	err = utils.WriteJSON(tmpFile, s)
	if err != nil {
		return err
	}
	err = tmpFile.Close()
	if err != nil {
		return err
	}

	stateFilePath := filepath.Join(c.root, stateFilename)
	return os.Rename(tmpFile.Name(), stateFilePath)
}

func (c *linuxContainer) currentStatus() (Status, error) {
	if err := c.refreshState(); err != nil {
		return -1, err
	}
	return c.state.status(), nil
}

// refreshState needs to be called to verify that the current state on the
// container is what is true.  Because consumers of libcontainer can use it
// out of process we need to verify the container's status based on runtime
// information and not rely on our in process info.
func (c *linuxContainer) refreshState() error {
	paused, err := c.isPaused()
	if err != nil {
		return err
	}
	if paused {
		return c.state.transition(&pausedState{c: c})
	}
	t := c.runType()
	switch t {
	case Created:
		return c.state.transition(&createdState{c: c})
	case Running:
		return c.state.transition(&runningState{c: c})
	}
	return c.state.transition(&stoppedState{c: c})
}

func (c *linuxContainer) runType() Status {
	if c.initProcess == nil {
		return Stopped
	}
	pid := c.initProcess.pid()
	stat, err := system.Stat(pid)
	if err != nil {
		return Stopped
	}
	if stat.StartTime != c.initProcessStartTime || stat.State == system.Zombie || stat.State == system.Dead {
		return Stopped
	}
	// We'll create exec fifo and blocking on it after container is created,
	// and delete it after start container.
	if _, err := os.Stat(filepath.Join(c.root, execFifoFilename)); err == nil {
		return Created
	}
	return Running
}

func (c *linuxContainer) isPaused() (bool, error) {
	state, err := c.cgroupManager.GetFreezerState()
	if err != nil {
		return false, err
	}
	return state == configs.Frozen, nil
}

func (c *linuxContainer) currentState() (*State, error) {
	var (
		startTime           uint64
		externalDescriptors []string
		pid                 = -1
	)
	if c.initProcess != nil {
		pid = c.initProcess.pid()
		startTime, _ = c.initProcess.startTime()
		externalDescriptors = c.initProcess.externalDescriptors()
	}
	intelRdtPath, err := intelrdt.GetIntelRdtPath(c.ID())
	if err != nil {
		intelRdtPath = ""
	}
	state := &State{
		BaseState: BaseState{
			ID:                   c.ID(),
			Config:               *c.config,
			InitProcessPid:       pid,
			InitProcessStartTime: startTime,
			Created:              c.created,
		},
		Rootless:            c.config.RootlessEUID && c.config.RootlessCgroups,
		CgroupPaths:         c.cgroupManager.GetPaths(),
		IntelRdtPath:        intelRdtPath,
		NamespacePaths:      make(map[configs.NamespaceType]string),
		ExternalDescriptors: externalDescriptors,
		SysMgr:              *c.sysMgr,
		SysFs:               *c.sysFs,
	}

	if pid > 0 {
		for _, ns := range c.config.Namespaces {
			state.NamespacePaths[ns.Type] = ns.GetPath(pid)
		}
		for _, nsType := range configs.NamespaceTypes() {
			if !configs.IsNamespaceSupported(nsType) {
				continue
			}
			if _, ok := state.NamespacePaths[nsType]; !ok {
				ns := configs.Namespace{Type: nsType}
				state.NamespacePaths[ns.Type] = ns.GetPath(pid)
			}
		}
	}
	return state, nil
}

func (c *linuxContainer) currentOCIState() (*specs.State, error) {
	bundle, annotations := utils.Annotations(c.config.Labels)
	state := &specs.State{
		Version:     specs.Version,
		ID:          c.ID(),
		Bundle:      bundle,
		Annotations: annotations,
	}
	status, err := c.currentStatus()
	if err != nil {
		return nil, err
	}
	state.Status = specs.ContainerState(status.String())
	if status != Stopped {
		if c.initProcess != nil {
			state.Pid = c.initProcess.pid()
		}
	}
	return state, nil
}

// orderNamespacePaths sorts namespace paths into a list of paths that we
// can setns in order.
func (c *linuxContainer) orderNamespacePaths(namespaces map[configs.NamespaceType]string) ([]string, error) {
	paths := []string{}
	for _, ns := range configs.NamespaceTypes() {

		// Remove namespaces that we don't need to join.
		if !c.config.Namespaces.Contains(ns) {
			continue
		}

		if p, ok := namespaces[ns]; ok && p != "" {
			// check if the requested namespace is supported
			if !configs.IsNamespaceSupported(ns) {
				return nil, newSystemError(fmt.Errorf("namespace %s is not supported", ns))
			}
			// only set to join this namespace if it exists
			if _, err := os.Lstat(p); err != nil {
				return nil, newSystemErrorWithCausef(err, "running lstat on namespace path %q", p)
			}
			// do not allow namespace path with comma as we use it to separate
			// the namespace paths
			if strings.ContainsRune(p, ',') {
				return nil, newSystemError(fmt.Errorf("invalid path %s", p))
			}
			paths = append(paths, fmt.Sprintf("%s:%s", configs.NsName(ns), p))
		}

	}

	return paths, nil
}

func encodeIDMapping(idMap []configs.IDMap) ([]byte, error) {
	data := bytes.NewBuffer(nil)
	for _, im := range idMap {
		line := fmt.Sprintf("%d %d %d\n", im.ContainerID, im.HostID, im.Size)
		if _, err := data.WriteString(line); err != nil {
			return nil, err
		}
	}
	return data.Bytes(), nil
}

// bootstrapData encodes the necessary data in netlink binary format
// as a io.Reader.
// Consumer can write the data to a bootstrap program
// such as one that uses nsenter package to bootstrap the container's
// init process correctly, i.e. with correct namespaces, uid/gid
// mapping etc.
func (c *linuxContainer) bootstrapData(cloneFlags uintptr, nsMaps map[configs.NamespaceType]string) (io.Reader, error) {
	// create the netlink message
	r := nl.NewNetlinkRequest(int(InitMsg), 0)

	// write cloneFlags
	r.AddData(&Int32msg{
		Type:  CloneFlagsAttr,
		Value: uint32(cloneFlags),
	})

	// write custom namespace paths
	if len(nsMaps) > 0 {
		nsPaths, err := c.orderNamespacePaths(nsMaps)
		if err != nil {
			return nil, err
		}
		r.AddData(&Bytemsg{
			Type:  NsPathsAttr,
			Value: []byte(strings.Join(nsPaths, ",")),
		})
	}

	// write uid & gid mappings only when we create a new user-ns
	_, joinExistingUser := nsMaps[configs.NEWUSER]
	if !joinExistingUser {
		// write uid mappings
		if len(c.config.UidMappings) > 0 {
			if c.config.RootlessEUID && c.newuidmapPath != "" {
				r.AddData(&Bytemsg{
					Type:  UidmapPathAttr,
					Value: []byte(c.newuidmapPath),
				})
			}
			b, err := encodeIDMapping(c.config.UidMappings)
			if err != nil {
				return nil, err
			}
			r.AddData(&Bytemsg{
				Type:  UidmapAttr,
				Value: b,
			})
		}

		// write gid mappings
		if len(c.config.GidMappings) > 0 {
			b, err := encodeIDMapping(c.config.GidMappings)
			if err != nil {
				return nil, err
			}
			r.AddData(&Bytemsg{
				Type:  GidmapAttr,
				Value: b,
			})
			if c.config.RootlessEUID && c.newgidmapPath != "" {
				r.AddData(&Bytemsg{
					Type:  GidmapPathAttr,
					Value: []byte(c.newgidmapPath),
				})
			}
			if requiresRootOrMappingTool(c.config) {
				r.AddData(&Boolmsg{
					Type:  SetgroupAttr,
					Value: true,
				})
			}
		}
	}

	if c.config.OomScoreAdj != nil {
		// write the configured oom_score_adj
		r.AddData(&Bytemsg{
			Type:  OomScoreAdjAttr,
			Value: []byte(strconv.Itoa(*c.config.OomScoreAdj)),
		})
	} else {
		// Pass sysbox's oom_score_adj explicitly to nsenter; this is needed because nsenter
		// initially sets the oom_score_adj to -999 and later reverts it to the given value
		// (so as to allow child processes to set -999 if desired).  By passing it here, we
		// honor the OCI spec: "If oomScoreAdj is not set, the runtime MUST NOT change the
		// value of oom_score_adj."
		var err error

		f, err := os.Open("/proc/self/oom_score_adj")
		if err != nil {
			return nil, err
		}
		defer f.Close()

		str, err := bufio.NewReader(f).ReadString('\n')
		if err != nil {
			return nil, err
		}

		str = strings.Trim(str, "\n")

		selfOomScoreAdj, err := strconv.Atoi(str)
		if err != nil {
			return nil, err
		}

		// For sys containers we don't allow -1000 for the OOM score value, as this
		// is not supported from within a user-ns.
		if selfOomScoreAdj < -999 {
			selfOomScoreAdj = -999
		}

		r.AddData(&Bytemsg{
			Type:  OomScoreAdjAttr,
			Value: []byte(strconv.Itoa(selfOomScoreAdj)),
		})
	}

	// write rootless
	r.AddData(&Boolmsg{
		Type:  RootlessEUIDAttr,
		Value: c.config.RootlessEUID,
	})

	// sysbox-runc: request prep of the rootfs when we create a new mnt-ns
	_, joinExistingMnt := nsMaps[configs.NEWNS]
	if !joinExistingMnt {

		r.AddData(&Boolmsg{
			Type:  PrepRootfsAttr,
			Value: true,
		})

		makeParentPriv, parentMount, err := rootfsParentMountIsShared(c.config.Rootfs)
		if err != nil {
			return nil, err
		}

		r.AddData(&Boolmsg{
			Type:  MakeParentPrivAttr,
			Value: makeParentPriv,
		})

		r.AddData(&Bytemsg{
			Type:  ParentMountAttr,
			Value: []byte(parentMount),
		})

		propFlag := unix.MS_SLAVE | unix.MS_REC
		if c.config.RootPropagation != 0 {
			propFlag = c.config.RootPropagation
		}

		r.AddData(&Int32msg{
			Type:  RootfsPropAttr,
			Value: uint32(propFlag),
		})

		r.AddData(&Bytemsg{
			Type:  RootfsAttr,
			Value: []byte(c.config.Rootfs),
		})

		shiftfsMounts := []string{}
		for _, m := range c.config.ShiftfsMounts {
			shiftfsMounts = append(shiftfsMounts, m.Source)
		}

		r.AddData(&Bytemsg{
			Type:  ShiftfsMountsAttr,
			Value: []byte(strings.Join(shiftfsMounts, ",")),
		})

	}

	return bytes.NewReader(r.Serialize()), nil
}

// ignoreTerminateErrors returns nil if the given err matches an error known
// to indicate that the terminate occurred successfully or err was nil, otherwise
// err is returned unaltered.
func ignoreTerminateErrors(err error) error {
	if err == nil {
		return nil
	}
	// terminate() might return an error from ether Kill or Wait.
	// The (*Cmd).Wait documentation says: "If the command fails to run
	// or doesn't complete successfully, the error is of type *ExitError".
	// Filter out such errors (like "exit status 1" or "signal: killed").
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return nil
	}
	// TODO: use errors.Is(err, os.ErrProcessDone) here and
	// remove "process already finished" string comparison below
	// once go 1.16 is minimally supported version.

	s := err.Error()
	if strings.Contains(s, "process already finished") ||
		strings.Contains(s, "Wait was already called") {
		return nil
	}
	return err
}

func requiresRootOrMappingTool(c *configs.Config) bool {
	gidMap := []configs.IDMap{
		{ContainerID: 0, HostID: os.Getegid(), Size: 1},
	}
	return !reflect.DeepEqual(c.GidMappings, gidMap)
}

// Borrowed from https://golang.org/src/syscall/exec_linux.go  (BSD-license)
func formatIDMappings(idMap []configs.IDMap) []byte {
	var data []byte
	for _, im := range idMap {
		data = append(data, []byte(strconv.Itoa(im.ContainerID)+" "+strconv.Itoa(im.HostID)+" "+strconv.Itoa(im.Size)+"\n")...)
	}
	return data
}

// sysbox-runc: handleReqOp handles requests from the container's init process for actions
// that can't be done by it (e.g., due to lack of permissions, etc.).
func (c *linuxContainer) handleReqOp(childPid int, reqs []opReq) error {

	if len(reqs) == 0 {
		return newSystemError(fmt.Errorf("no op requests!"))
	}

	// If multiple requests are passed in the slice, they must all be
	// of the same type.
	op := reqs[0].Op

	if op != bind && op != switchDockerDns && op != chown && op != mkdir && op != rootfsIDMap {
		return newSystemError(fmt.Errorf("invalid opReq type %d", int(op)))
	}

	// Add the container's init process pid to the first op request
	reqs[0].InitPid = childPid

	return c.handleOp(op, childPid, reqs)
}

// sysbox-runc: handleOp dispatches a helpter process that enters one or more of
// the container's namespaces and performs the given request. By virtue of only
// entering a subset of the container's namespaces, the helper can bypass restrictions
// that the container's init process would have in order to perform those same actions.
func (c *linuxContainer) handleOp(op opReqType, childPid int, reqs []opReq) error {

	// create the socket pairs for communication with the new nsenter child process
	parentMsgPipe, childMsgPipe, err := utils.NewSockPair("initHelper")
	if err != nil {
		return newSystemErrorWithCause(err, "creating new initHelper pipe")
	}
	defer parentMsgPipe.Close()

	parentLogPipe, childLogPipe, err := os.Pipe()
	if err != nil {
		return newSystemErrorWithCause(err, "Unable to create the initMount log pipe")
	}

	// create a new initMount command
	initProc := c.initProcess.(*initProcess).process
	cmd := c.initHelperCmdTemplate(initProc, childMsgPipe, childLogPipe)

	// Log error messages from the initMount child process
	go logs.ForwardLogs(parentLogPipe)

	// start the command (creates parent, child, and grandchild
	// processes; the granchild enters the go-runtime in the desired
	// namespaces).
	err = cmd.Start()
	childMsgPipe.Close()
	childLogPipe.Close()
	if err != nil {
		return newSystemErrorWithCause(err, "starting initHelper child")
	}

	// create the config payload
	namespaces := []string{}

	switch op {
	case bind, chown, mkdir, rootfsIDMap:
		namespaces = append(namespaces,
			fmt.Sprintf("mnt:/proc/%d/ns/mnt", childPid),
			fmt.Sprintf("pid:/proc/%d/ns/pid", childPid),
		)
	case switchDockerDns:
		namespaces = append(namespaces,
			fmt.Sprintf("net:/proc/%d/ns/net", childPid),
		)
	}

	r := nl.NewNetlinkRequest(int(InitMsg), 0)
	r.AddData(&Bytemsg{
		Type:  NsPathsAttr,
		Value: []byte(strings.Join(namespaces, ",")),
	})

	// send the config to the parent process
	if _, err := io.Copy(parentMsgPipe, bytes.NewReader(r.Serialize())); err != nil {
		return newSystemErrorWithCause(err, "copying initHelper bootstrap data to pipe")
	}

	// wait for parent process to exit
	status, err := cmd.Process.Wait()
	if err != nil {
		cmd.Wait()
		return err
	}
	if !status.Success() {
		cmd.Wait()
		return newSystemError(&exec.ExitError{ProcessState: status})
	}

	// get the first child pid from the pipe
	var pid pid
	decoder := json.NewDecoder(parentMsgPipe)
	if err := decoder.Decode(&pid); err != nil {
		cmd.Wait()
		return newSystemErrorWithCause(err, "getting the initHelper pid from pipe")
	}

	firstChildProcess, err := os.FindProcess(pid.PidFirstChild)
	if err != nil {
		return err
	}

	// wait for the first child to exit; ignore errors in case the child has
	// already been reaped for any reason
	_, _ = firstChildProcess.Wait()

	// grandchild remains and will enter the go runtime
	process, err := os.FindProcess(pid.Pid)
	if err != nil {
		return err
	}
	cmd.Process = process

	// send the action requests to the grandchild
	if err := utils.WriteJSON(parentMsgPipe, reqs); err != nil {
		return newSystemErrorWithCause(err, "writing init mount info to pipe")
	}

	// wait for msg from the grandchild indicating that it's done
	ierr := parseSync(parentMsgPipe, func(sync *syncT) error {
		switch sync.Type {
		case opDone:
			// no further action; parseSync will wait for pipe to be closed on the other side.
		default:
			return newSystemError(fmt.Errorf("invalid JSON payload from initSetRootfs child"))
		}
		return nil
	})

	// destroy the socket pair
	if err := unix.Shutdown(int(parentMsgPipe.Fd()), unix.SHUT_WR); err != nil {
		return newSystemErrorWithCause(err, "shutting down initHelper pipe")
	}

	if ierr != nil {
		cmd.Wait()
		return ierr
	}

	cmd.Wait()
	return nil
}

// Processes a seccomp notification file-descriptor for the sys container by passing it to
// sysbox-fs to setup syscall trapping.
func (c *linuxContainer) procSeccompInit(pid int, fd int32) error {
	if c.sysFs.Enabled() {
		if err := c.sysFs.SendSeccompInit(pid, c.id, fd); err != nil {
			return newSystemErrorWithCause(err, "sending seccomp fd to sysbox-fs")
		}
	}
	return nil
}

// sysbox-runc: sets up the shiftfs marks for the container
func (c *linuxContainer) setupShiftfsMarks() error {

	mi, err := mount.GetMounts()
	if err != nil {
		return fmt.Errorf("failed to read mountinfo: %s", err)
	}

	config := c.config
	shiftfsMounts := []configs.ShiftfsMount{}

	// rootfs
	if config.RootfsUidShiftType == sh.Shiftfs ||
		config.RootfsUidShiftType == sh.IDMappedMountOrShiftfs {
		shiftfsMounts = append(shiftfsMounts, configs.ShiftfsMount{Source: config.Rootfs, Readonly: false})
	}

	// bind-mounts
	if config.BindMntUidShiftType == sh.Shiftfs ||
		config.BindMntUidShiftType == sh.IDMappedMountOrShiftfs {

		for _, m := range config.Mounts {
			if m.Device == "bind" {

				if m.IDMappedMount {
					continue
				}

				needShiftfs, err := needUidShiftOnBindSrc(m, config)
				if err != nil {
					return newSystemErrorWithCause(err, "checking uid shifting on bind source")
				}

				if !needShiftfs {
					continue
				}

				// If the mount source is a file, it may itself be a bind-mount from
				// another file. In this case, we need to mount shiftfs over the
				// orig file (i.e., the source of the bind mount).
				if !m.BindSrcInfo.IsDir {

					isBindMnt, origSrc, err := fileIsBindMount(mi, m.Source)
					if err != nil {
						return fmt.Errorf("failed to check if %s is a bind-mount: %s", m.Source, err)
					}

					if isBindMnt {
						m.Source = origSrc
					}
				}

				// shiftfs mounts must be on directories (not on files). But this
				// does not mean that the directory on which shiftfs is mounted is
				// necessarily fully exposed inside the container; it may be that
				// only a file in that directory is exposed inside the container
				// (via bind-mounts when setting up the container rootfs).

				var dir string
				if !m.BindSrcInfo.IsDir {
					dir = filepath.Dir(m.Source)
				} else {
					dir = m.Source
				}

				if skipShiftfsBindSource(dir) {
					continue
				}

				duplicate := false
				for _, sm := range shiftfsMounts {
					if sm.Source == dir {
						duplicate = true
					}
				}

				if !duplicate {
					sm := configs.ShiftfsMount{
						Source:   dir,
						Readonly: m.Flags&unix.MS_RDONLY == unix.MS_RDONLY,
					}
					shiftfsMounts = append(shiftfsMounts, sm)
				}
			}
		}
	}

	// Perform the shiftfs marks; normally this is done by sysbox-mgr as it can
	// track shiftfs mark-points on the host. But for sysbox-runc unit testing
	// the sysbox-mgr is not present, so we do the shiftfs marking locally (which
	// only works when sys containers are not sharing mount points).

	if c.sysMgr.Enabled() {

		shiftfsMarks, err := c.sysMgr.ReqShiftfsMark(shiftfsMounts)
		if err != nil {
			return err
		}

		if len(shiftfsMarks) != len(shiftfsMounts) {
			return fmt.Errorf("Error creating shiftfs mark-mounts: shiftfsMounts = %v, shiftfsMarks = %v",
				shiftfsMounts, shiftfsMarks)
		}

		config.ShiftfsMounts = shiftfsMarks

		// Replace the container's mounts that have shiftfs with the shiftfs
		// markpoint allocated by sysbox-mgr.

		if config.RootfsUidShiftType == sh.Shiftfs {
			config.Rootfs = shiftfsMarks[0].Source
		}

		for _, m := range config.Mounts {
			if m.Device == "bind" {
				if m.BindSrcInfo.IsDir {
					for i, sm := range shiftfsMounts {
						if m.Source == sm.Source {
							m.Source = shiftfsMarks[i].Source
						}
					}
				} else {
					for i, sm := range shiftfsMounts {
						if filepath.Dir(m.Source) == sm.Source {
							m.Source = filepath.Join(shiftfsMarks[i].Source, filepath.Base(m.Source))
						}
					}
				}
			}
		}

		return nil

	} else {
		config.ShiftfsMounts = shiftfsMounts
		return c.setupShiftfsMarkLocal(mi)
	}
}

// Setup shiftfs marks; meant for testing only
func (c *linuxContainer) setupShiftfsMarkLocal(mi []*mount.Info) error {

	for _, m := range c.config.ShiftfsMounts {
		mounted, err := mount.MountedWithFs(m.Source, "shiftfs", mi)
		if err != nil {
			return newSystemErrorWithCausef(err, "checking for shiftfs mount at %s", m.Source)
		}
		if !mounted {
			if err := shiftfs.Mark(m.Source, m.Source); err != nil {
				return newSystemErrorWithCausef(err, "marking shiftfs on %s", m.Source)
			}
		}
	}

	return nil
}

// Teardown shiftfs marks; meant for testing only
func (c *linuxContainer) teardownShiftfsMarkLocal(mi []*mount.Info) error {

	for _, m := range c.config.ShiftfsMounts {
		mounted, err := mount.MountedWithFs(m.Source, "shiftfs", mi)
		if err != nil {
			return newSystemErrorWithCausef(err, "checking for shiftfs mount at %s", m.Source)
		}
		if mounted {
			if err := shiftfs.Unmount(m.Source); err != nil {
				return newSystemErrorWithCausef(err, "unmarking shiftfs on %s", m.Source)
			}
		}
	}

	return nil
}

func (c *linuxContainer) rootfsCloningRequired() (bool, error) {

	// If the rootfs is on an overlayfs mount, then chown can be very slow (in
	// the order of many seconds because it triggers a "copy-up" of every file),
	// unless the overlay was mounted with "metacopy=on". If metacopy is disabled
	// (e.g., Docker does not set this option), then we need a solution.
	//
	// Turns out we can't simply add the "metacopy=on" to the existing overlayfs
	// mount on the rootfs via a remount (it's not supported). We could unmount
	// and then remount, but the unmount may break the container manager that set
	// up the mount. We tried, it did not work (Docker/containerd did not like
	// it).
	//
	// The solution is to ask the sysbox-mgr to clone the rootfs at a separate
	// location, and mount the overlay with metacopy=on. We will then setup the
	// container using this cloned rootfs.

	if !c.sysMgr.Enabled() {
		return false, nil
	}

	rootfs := c.config.Rootfs
	mounts, err := mount.GetMounts()

	mi, err := mount.GetMountAt(rootfs, mounts)
	if err == nil && mi.Fstype == "overlay" && !strings.Contains(mi.Opts, "metacopy=on") {
		return true, nil
	}

	return false, nil
}

// chowns the container's rootfs to match the user-ns uid & gid mappings.
func (c *linuxContainer) chownRootfs() error {

	rootfs := c.config.Rootfs

	uidOffset := int32(c.config.UidMappings[0].HostID)
	gidOffset := int32(c.config.GidMappings[0].HostID)

	if err := sh.ShiftIdsWithChown(rootfs, uidOffset, gidOffset); err != nil {
		return newSystemErrorWithCausef(err, "chowning rootfs at %s by offset %d, %d", rootfs, uidOffset, gidOffset)
	}

	return nil
}

// reverts the container's rootfs chown (back to it's original value)
func (c *linuxContainer) revertRootfsChown() error {

	if c.sysMgr.IsRootfsCloned() {
		c.config.Rootfs = c.sysMgr.GetClonedRootfs()
	}

	uidOffset := 0 - int32(c.config.UidMappings[0].HostID)
	gidOffset := 0 - int32(c.config.GidMappings[0].HostID)

	if err := sh.ShiftIdsWithChown(c.config.Rootfs, uidOffset, gidOffset); err != nil {
		return newSystemErrorWithCausef(err, "chowning rootfs at %s by offset %d, %d", c.config.Rootfs, uidOffset, gidOffset)
	}

	return nil
}

// The following are host directories where we never mount shiftfs as it causes functional problems.
var shiftfsBlackList = []string{"/dev"}

// sysbox-runc: skipShiftfsBindSource indicates if shiftfs mounts should be skipped on the
// given directory.
func skipShiftfsBindSource(source string) bool {
	for _, m := range shiftfsBlackList {
		if source == m {
			return true
		}
	}

	// Don't mount shiftfs on cgroup v2 bind-source either
	if strings.HasPrefix(source, "/sys/fs/cgroup") {
		return true
	}

	return false
}

// sysbox-runc: determines which mounts must be ID-mapped; does not actually
// perform the ID-mapped mounts (that's done inside the container, see
// rootfs_init_linux.go) but rather marks the mount for ID-mapping only.
func (c *linuxContainer) setupIDMappedMounts() error {

	config := c.config

	// rootfs
	if config.RootfsUidShiftType == sh.IDMappedMount ||
		config.RootfsUidShiftType == sh.IDMappedMountOrShiftfs {
		idMapMountAllowed, err := idMap.IDMapMountSupportedOnPath(config.Rootfs)
		if err != nil {
			return newSystemErrorWithCausef(err, "checking for ID-mapped mount support on rootfs %s", config.Rootfs)
		}
		if idMapMountAllowed {
			config.RootfsUidShiftType = sh.IDMappedMount
		}
	}

	// bind-mounts
	if config.BindMntUidShiftType == sh.IDMappedMount ||
		config.BindMntUidShiftType == sh.IDMappedMountOrShiftfs {

		for _, m := range config.Mounts {
			if m.Device == "bind" {

				idMapMntAllowed, err := idMap.IDMapMountSupportedOnPath(m.Source)
				if err != nil {
					return newSystemErrorWithCausef(err, "checking for ID-mapped mount support on bind source %s", m.Source)
				}

				if !idMapMntAllowed {
					continue
				}

				needIDMap, err := needUidShiftOnBindSrc(m, config)
				if err != nil {
					return newSystemErrorWithCause(err, "checking uid shifting on bind source")
				}

				m.IDMappedMount = needIDMap
			}
		}
	}

	return nil
}

// needUidShiftOnBindSrc checks if uid/gid shifting on the given bind mount source path is
// required to run the system container.
func needUidShiftOnBindSrc(mount *configs.Mount, config *configs.Config) (bool, error) {

	// sysbox-fs handles uid(gid) shifting itself, so no need for mounting shiftfs on top
	if strings.HasPrefix(mount.Source, syscont.SysboxFsDir+"/") {
		return false, nil
	}

	// Don't uid shift on bind sources under the container's rootfs
	if strings.HasPrefix(mount.Source, config.Rootfs+"/") {
		return false, nil
	}

	// If the bind source has uid:gid ownership matching the container's user-ns
	// mappings, uid shifting is not needed.

	var hostUid, hostGid uint32
	var uidSize, gidSize uint32

	for _, mapping := range config.UidMappings {
		if mapping.ContainerID == 0 {
			hostUid = uint32(mapping.HostID)
		}
		uidSize += uint32(mapping.Size)
	}
	for _, mapping := range config.GidMappings {
		if mapping.ContainerID == 0 {
			hostGid = uint32(mapping.HostID)
		}
		gidSize += uint32(mapping.Size)
	}

	if (mount.BindSrcInfo.Uid >= hostUid) && (mount.BindSrcInfo.Uid < hostUid+uidSize) &&
		(mount.BindSrcInfo.Gid >= hostGid) && (mount.BindSrcInfo.Gid < hostGid+gidSize) {
		return false, nil
	}

	return true, nil
}

// Checks if the file at the given path is a bind-mount; if so, returns true and
// the path to the bind-mount's source.
func fileIsBindMount(mounts []*mount.Info, fpath string) (bool, string, error) {
	var fpathMi *mount.Info

	// Since path corresponds to a file (not a directory), if it's a mountpoint
	// then it must be a bind-mount (i.e., file mountpoints are only allowed for
	// bind mounts).
	for _, mi := range mounts {
		if mi.Mountpoint == fpath {
			fpathMi = mi
			break
		}
	}

	// If file is not a mountpoint, we are done
	if fpathMi == nil {
		return false, "", nil
	}

	// Find the source of that bind mount. This is not as simple as looking at
	// the fpathMi.Root, because the root itself may be a bind-mount. To resolve
	// this, we find the device that backs the file, then find where that device
	// is mounted at (the device's root mountpoint), and then use it to replace
	// the correponding prefix in the fpathMi.Root.
	//
	// For example: say fpath = /mnt/scratch/t1/f1 and the mount tree looks like:
	//
	// 1232 1303 0:60 / /mnt/scratch/tmpfs rw,relatime - tmpfs tmpfs rw,size=10240k
	// 1233 1303 0:60 /f1-tmpfs /mnt/scratch/t1/f1 rw,relatime - tmpfs tmpfs rw,size=10240k
	//
	// Then we see that mount 1232 is the root mount for the device and it's mounted at "/mnt/scratch/tmpfs".
	// Thus, we replace /f1-tmpfs -> /mnt/scratch/tmpfs/f1-tmpfs.
	//
	// Another example: say fpath = /mnt/scratch/t1/f3 and the mount tree looks like:
	//
	// 1302 1282 8:2 /var/tmp/sysbox-test-var-run /run rw,relatime - ext4 /dev/sda2 rw
	// 1303 1282 8:2 /var/tmp/sysbox-test-scratch /mnt/scratch rw,relatime - ext4 /dev/sda2 rw
	// 1234 1303 8:2 /var/tmp/sysbox-test-scratch/t1/f4 /mnt/scratch/t1/f3 rw,relatime - ext4 /dev/sda2 rw
	//
	// Then we see that mount 1303 is the root mount for the device and it's mounted at "/mnt/scratch".
	// Thus, we replace /var/tmp/sysbox-test-scratch/t1/f4 -> /mnt/scratch/t1/f4.

	devRoot := fpathMi.Root
	devMp := ""

	for _, mi := range mounts {
		if mi.Major == fpathMi.Major && mi.Minor == fpathMi.Minor {
			if strings.HasPrefix(devRoot, mi.Root) {
				devRoot = mi.Root
				devMp = mi.Mountpoint
			}
		}
	}

	// The extra "/" ensures we have a path separator in the resulting path
	fpathMi.Root = strings.Replace(fpathMi.Root, devRoot, devMp+"/", 1)
	return true, fpathMi.Root, nil
}
