//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

// Exposes functions for sysbox-runc to interact with sysbox-fs

package sysbox

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/nestybox/sysbox-ipc/sysboxFsGrpc"

	fdlib "github.com/ftrvxmtrx/fd"
)

// FsRegInfo contains info about a container registered with sysbox-fs
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
	Reg    bool   // indicates if container was registered with sysbox-mgr
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

// Registers container info with with sysbox-fs
func (fs *Fs) Register(info *FsRegInfo) error {
	if fs.Reg {
		return fmt.Errorf("container %v already registered", fs.Id)
	}
	data := &sysboxFsGrpc.ContainerData{
		Id:       fs.Id,
		InitPid:  int32(info.Pid),
		Hostname: info.Hostname,
		UidFirst: int32(info.Uid),
		UidSize:  int32(info.IdSize),
		GidFirst: int32(info.Gid),
		GidSize:  int32(info.IdSize),
	}
	if err := sysboxFsGrpc.SendContainerRegistration(data); err != nil {
		return fmt.Errorf("failed to register with sysbox-fs: %v", err)
	}
	fs.Reg = true
	return nil
}

// Sends container creation time to sysbox-fs
func (fs *Fs) SendCreationTime(t time.Time) error {
	if !fs.Reg {
		return fmt.Errorf("must register container %v before", fs.Id)
	}
	data := &sysboxFsGrpc.ContainerData{
		Id:    fs.Id,
		Ctime: t,
	}
	if err := sysboxFsGrpc.SendContainerUpdate(data); err != nil {
		return fmt.Errorf("failed to send creation time to sysbox-fs: %v", err)
	}
	return nil
}

func (fs *Fs) SendSeccompFd(id string, seccompFd int32) error {

	// TODO: complete this function; send fd to sysbox-fs and wait for its ack.

	return sendFdToTracer(seccompFd)
}

// Unregisters the container with with sysbox-fs
func (fs *Fs) Unregister() error {
	if fs.Reg {
		data := &sysboxFsGrpc.ContainerData{
			Id: fs.Id,
		}
		if err := sysboxFsGrpc.SendContainerUnregistration(data); err != nil {
			return fmt.Errorf("failed to unregister with sysbox-fs: %v", err)
		}
		fs.Reg = false
	}
	return nil
}

// XXX: DEBUG

const (
	tracerSock = "/tmp/seccomp-tracer"
)

// Send the given seccomp notifFd to the tracer program (assumed to be running already)
func sendFdToTracer(notifFd int32) error {

	addr, err := net.ResolveUnixAddr("unix", tracerSock)
	if err != nil {
		return fmt.Errorf("Failed to resolve %s: %v\n", tracerSock, err)
	}

	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return fmt.Errorf("Failed to dial: %v\n", err)
	}
	defer conn.Close()

	file := os.NewFile(uintptr(notifFd), "notifFd")
	if err := fdlib.Put(conn, file); err != nil {
		return fmt.Errorf("failed to send file descriptor: %v\n", err)
	}

	buf := make([]byte, 3)
	_, err = conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read from connection: %v\n", err)
	}

	if string(buf) != "ack" {
		return fmt.Errorf("invalid ack: %v", buf)
	}

	return nil
}
