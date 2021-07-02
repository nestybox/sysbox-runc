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

// Exposes functions for sysbox-runc to interact with sysbox-mgr

package sysbox

import (
	"fmt"

	"github.com/nestybox/sysbox-ipc/sysboxMgrGrpc"
	ipcLib "github.com/nestybox/sysbox-ipc/sysboxMgrLib"
	"github.com/opencontainers/runc/libcontainer/configs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type Mgr struct {
	Active bool
	Id     string                  // container-id
	Config *ipcLib.ContainerConfig // sysbox-mgr mandated container config
}

func NewMgr(id string, enable bool) *Mgr {
	return &Mgr{
		Active: enable,
		Id:     id,
		Config: &ipcLib.ContainerConfig{
			AliasDns:          true,
			BindMountUidShift: true,
		},
	}
}

func (mgr *Mgr) Enabled() bool {
	return mgr.Active
}

// Registers the container with sysbox-mgr. If successful, stores the
// sysbox configuration tokens for sysbox-runc in mgr.Config
func (mgr *Mgr) Register(spec *specs.Spec) error {
	var userns string
	var netns string

	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.UserNamespace && ns.Path != "" {
			userns = ns.Path
		}
		if ns.Type == specs.NetworkNamespace && ns.Path != "" {
			netns = ns.Path
		}
	}

	regInfo := &ipcLib.RegistrationInfo{
		Id:          mgr.Id,
		Userns:      userns,
		Netns:       netns,
		UidMappings: spec.Linux.UIDMappings,
		GidMappings: spec.Linux.GIDMappings,
	}

	config, err := sysboxMgrGrpc.Register(regInfo)
	if err != nil {
		return fmt.Errorf("failed to register with sysbox-mgr: %v", err)
	}

	mgr.Config = config

	return nil
}

func (mgr *Mgr) Update(userns, netns string, uidMappings, gidMappings []specs.LinuxIDMapping) error {

	updateInfo := &ipcLib.UpdateInfo{
		Id:          mgr.Id,
		Userns:      userns,
		Netns:       netns,
		UidMappings: uidMappings,
		GidMappings: gidMappings,
	}

	if err := sysboxMgrGrpc.Update(updateInfo); err != nil {
		return fmt.Errorf("failed to update container info with sysbox-mgr: %v", err)
	}
	return nil
}

// Unregisters the container with sysbox-mgr.
func (mgr *Mgr) Unregister() error {
	if err := sysboxMgrGrpc.Unregister(mgr.Id); err != nil {
		return fmt.Errorf("failed to unregister with sysbox-mgr: %v", err)
	}
	return nil
}

// ReqSubid requests sysbox-mgr to allocate uid & gids for the container user-ns.
func (mgr *Mgr) ReqSubid(size uint32) (uint32, uint32, error) {
	uid, gid, err := sysboxMgrGrpc.SubidAlloc(mgr.Id, uint64(size))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to request subid from sysbox-mgr: %v", err)
	}
	return uid, gid, nil
}

// PrepMounts sends a request to sysbox-mgr for prepare the given  container mounts; all paths must be absolute.
func (mgr *Mgr) PrepMounts(uid, gid uint32, prepList []ipcLib.MountPrepInfo) error {
	if err := sysboxMgrGrpc.PrepMounts(mgr.Id, uid, gid, prepList); err != nil {
		return fmt.Errorf("failed to request mount source preps from sysbox-mgr: %v", err)
	}
	return nil
}

// ReqMounts sends a request to sysbox-mgr for container mounts; all paths must be absolute.
func (mgr *Mgr) ReqMounts(rootfs string, uid, gid uint32, shiftUids bool, reqList []ipcLib.MountReqInfo) ([]specs.Mount, error) {
	mounts, err := sysboxMgrGrpc.ReqMounts(mgr.Id, rootfs, uid, gid, shiftUids, reqList)
	if err != nil {
		return nil, fmt.Errorf("failed to request mounts from sysbox-mgr: %v", err)
	}
	return mounts, nil
}

// ReqShiftfsMark sends a request to sysbox-mgr to mark shiftfs on the given dirs; all paths must be absolute.
func (mgr *Mgr) ReqShiftfsMark(mounts []configs.ShiftfsMount) ([]configs.ShiftfsMount, error) {
	resp, err := sysboxMgrGrpc.ReqShiftfsMark(mgr.Id, mounts)
	if err != nil {
		return nil, fmt.Errorf("failed to request shiftfs marking to sysbox-mgr: %v", err)
	}
	return resp, nil
}

// ReqFsState sends a request to sysbox-mgr for container's rootfs state.
func (mgr *Mgr) ReqFsState(rootfs string) ([]configs.FsEntry, error) {
	state, err := sysboxMgrGrpc.ReqFsState(mgr.Id, rootfs)
	if err != nil {
		return nil, fmt.Errorf("failed to request fsState from sysbox-mgr: %v", err)
	}

	return state, nil
}

func (mgr *Mgr) Pause() error {
	if err := sysboxMgrGrpc.Pause(mgr.Id); err != nil {
		return fmt.Errorf("failed to notify pause to sysbox-mgr: %v", err)
	}
	return nil
}
