//
// Copyright 2019-2020 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Exposes functions for sysbox-runc to interact with sysbox-fs

package sysbox

import (
	"fmt"
	"time"

	"github.com/nestybox/sysbox-ipc/sysboxFsGrpc"
	unixIpc "github.com/nestybox/sysbox-ipc/unix"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// FsRegInfo contains info about a sys container registered with sysbox-fs
type FsRegInfo struct {
	Hostname      string
	Pid           int
	Uid           int
	Gid           int
	IdSize        int
	ProcRoPaths   []string
	ProcMaskPaths []string
}

type Fs struct {
	Active     bool
	Id         string // container-id
	PreReg     bool   // indicates if the container was pre-registered with sysbox-fs
	Reg        bool   // indicates if sys container was registered with sysbox-fs
	Mountpoint string // sysbox-fs FUSE mountpoint
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

func (fs *Fs) GetConfig() error {

	mp, err := sysboxFsGrpc.GetMountpoint()
	if err != nil {
		return fmt.Errorf("failed to get config from sysbox-fs: %v", err)
	}

	fs.Mountpoint = mp
	return nil
}

// Pre-registers container with sysbox-fs.
func (fs *Fs) PreRegister(linuxNamespaces []specs.LinuxNamespace) error {
	if fs.PreReg {
		return fmt.Errorf("container %v already pre-registered", fs.Id)
	}

	data := &sysboxFsGrpc.ContainerData{
		Id: fs.Id,
	}

	// If the new container is entering an existing net-ns, pass the ns info to
	// sysbox-fs; containers which share the same net-ns see a common view of
	// the resources emulated by sysbox-fs (e.g., as in Kubernetes pods or
	// "docker run --net=container:<id> some-image").
	for _, ns := range linuxNamespaces {
		if ns.Type == specs.NetworkNamespace && ns.Path != "" {
			data.Netns = ns.Path
		}
	}

	if err := sysboxFsGrpc.SendContainerPreRegistration(data); err != nil {
		return fmt.Errorf("failed to pre-register with sysbox-fs: %v", err)
	}

	fs.PreReg = true

	return nil
}

// Registers container with sysbox-fs.
func (fs *Fs) Register(info *FsRegInfo) error {

	if !fs.PreReg {
		return fmt.Errorf("container %v was not pre-registered", fs.Id)
	}

	if fs.Reg {
		return fmt.Errorf("container %v already registered", fs.Id)
	}

	data := &sysboxFsGrpc.ContainerData{
		Id:            fs.Id,
		InitPid:       int32(info.Pid),
		Hostname:      info.Hostname,
		UidFirst:      int32(info.Uid),
		UidSize:       int32(info.IdSize),
		GidFirst:      int32(info.Gid),
		GidSize:       int32(info.IdSize),
		ProcRoPaths:   info.ProcRoPaths,
		ProcMaskPaths: info.ProcMaskPaths,
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

// Sends the seccomp-notification fd to sysbox-fs (tracer) to setup syscall
// trapping and waits for its response (ack).
func (fs *Fs) SendSeccompInit(pid int, id string, seccompFd int32) error {

	// TODO: Think about a better location for this one.
	const seccompTracerSockAddr = "/run/sysbox/sysfs-seccomp.sock"

	conn, err := unixIpc.Connect(seccompTracerSockAddr)
	if err != nil {
		return fmt.Errorf("Unable to establish connection with seccomp-tracer: %v\n", err)
	}

	if err = unixIpc.SendSeccompInitMsg(conn, int32(pid), id, seccompFd); err != nil {
		return fmt.Errorf("Unable to send message to seccomp-tracer: %v\n", err)
	}

	if err = unixIpc.RecvSeccompInitAckMsg(conn); err != nil {
		return fmt.Errorf("Unable to receive expected seccomp-notif-ack message: %v\n", err)
	}

	return nil
}

// Unregisters the container with sysbox-fs
func (fs *Fs) Unregister() error {
	if fs.PreReg || fs.Reg {
		data := &sysboxFsGrpc.ContainerData{
			Id: fs.Id,
		}
		if err := sysboxFsGrpc.SendContainerUnregistration(data); err != nil {
			return fmt.Errorf("failed to unregister with sysbox-fs: %v", err)
		}
		fs.PreReg = false
		fs.Reg = false
	}
	return nil
}
