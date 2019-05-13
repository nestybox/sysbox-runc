package sysbox

import (
	"fmt"
	"time"

	"github.com/nestybox/sysbox-ipc/sysboxFsGrpc"
)

// FsRegInfo contains info about a container registered with sysbox-fs
type FsRegInfo struct {
	Id       string
	Hostname string
	Pid      int
	Uid      int
	Gid      int
	IdSize   int
}

// Fs represents the sysbox-fs within sysbox-runc
type Fs struct {
	Active bool
	Id     string
}

func NewFs(enable bool) *Fs {
	return &Fs{
		Active: enable,
	}
}

func (fs *Fs) Enabled() bool {
	return fs.Active
}

// Registers the given container info with with sysbox-fs
func (fs *Fs) Register(info *FsRegInfo) error {
	if fs.Id != "" {
		return fmt.Errorf("container %v already registered", fs.Id)
	}
	data := &sysboxFsGrpc.ContainerData{
		Id:       info.Id,
		InitPid:  int32(info.Pid),
		Hostname: info.Hostname,
		UidFirst: int32(info.Uid),
		UidSize:  int32(info.IdSize),
		GidFirst: int32(info.Gid),
		GidSize:  int32(info.IdSize),
	}
	if err := sysboxFsGrpc.SendContainerRegistration(data); err != nil {
		return err
	}
	fs.Id = info.Id
	return nil
}

// Sends container creation time to sysbox-fs
func (fs *Fs) SendCreationTime(t time.Time) error {
	if fs.Id == "" {
		return fmt.Errorf("no container id found")
	}
	data := &sysboxFsGrpc.ContainerData{
		Id:    fs.Id,
		Ctime: t,
	}
	if err := sysboxFsGrpc.SendContainerUpdate(data); err != nil {
		return err
	}
	return nil
}

// Unregisters the given container with with sysbox-fs
func (fs *Fs) Unregister() error {
	if fs.Id != "" {
		data := &sysboxFsGrpc.ContainerData{
			Id: fs.Id,
		}
		if err := sysboxFsGrpc.SendContainerUnregistration(data); err != nil {
			return err
		}
		fs.Id = ""
	}
	return nil
}
