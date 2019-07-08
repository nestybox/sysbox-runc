// Exposes functions for sysvisor-runc to interact with sysvisor-fs

package sysvisor

import (
	"fmt"
	"time"

	"github.com/nestybox/sysvisor-ipc/sysvisorFsGrpc"
)

// FsRegInfo contains info about a container registered with sysvisor-fs
type FsRegInfo struct {
	Hostname string
	Pid      int
	Uid      int
	Gid      int
	IdSize   int
}

type Fs struct {
	Active bool
	Id     string // container-id
	Reg    bool   // indicates if container was registered with sysvisor-mgr
}

func NewFs(id string, enable bool) *Fs {
	return &Fs{
		Active: enable,
		Id:     id,
	}
}

func (fs *Fs) Enabled() bool {
	return fs.Active
}

// Registers container info with with sysvisor-fs
func (fs *Fs) Register(info *FsRegInfo) error {
	if fs.Reg {
		return fmt.Errorf("container %v already registered", fs.Id)
	}
	data := &sysvisorFsGrpc.ContainerData{
		Id:       fs.Id,
		InitPid:  int32(info.Pid),
		Hostname: info.Hostname,
		UidFirst: int32(info.Uid),
		UidSize:  int32(info.IdSize),
		GidFirst: int32(info.Gid),
		GidSize:  int32(info.IdSize),
	}
	if err := sysvisorFsGrpc.SendContainerRegistration(data); err != nil {
		return fmt.Errorf("failed to register with sysvisor-fs: %v", err)
	}
	fs.Reg = true
	return nil
}

// Sends container creation time to sysvisor-fs
func (fs *Fs) SendCreationTime(t time.Time) error {
	if !fs.Reg {
		return fmt.Errorf("must register container %v before", fs.Id)
	}
	data := &sysvisorFsGrpc.ContainerData{
		Id:    fs.Id,
		Ctime: t,
	}
	if err := sysvisorFsGrpc.SendContainerUpdate(data); err != nil {
		return fmt.Errorf("failed to send creation time to sysvisor-fs: %v", err)
	}
	return nil
}

// Unregisters the container with with sysvisor-fs
func (fs *Fs) Unregister() error {
	if fs.Reg {
		data := &sysvisorFsGrpc.ContainerData{
			Id: fs.Id,
		}
		if err := sysvisorFsGrpc.SendContainerUnregistration(data); err != nil {
			return fmt.Errorf("failed to unregister with sysvisor-fs: %v", err)
		}
		fs.Reg = false
	}
	return nil
}
