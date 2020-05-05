//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
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
	Id     string // container-id
}

func NewMgr(id string, enable bool) *Mgr {
	return &Mgr{
		Active: enable,
		Id:     id,
	}
}

func (mgr *Mgr) Enabled() bool {
	return mgr.Active
}

// Register registers the container with sysbox-mgr.
func (mgr *Mgr) Register() error {
	if _, err := sysboxMgrGrpc.Register(mgr.Id); err != nil {
		return fmt.Errorf("failed to register with sysbox-mgr: %v", err)
	}
	return nil
}

// Unregister unregisters the container with sysbox-mgr.
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
func (mgr *Mgr) PrepMounts(uid, gid uint32, shiftUids bool, prepList []ipcLib.MountPrepInfo) error {
	if err := sysboxMgrGrpc.PrepMounts(mgr.Id, uid, gid, shiftUids, prepList); err != nil {
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
func (mgr *Mgr) ReqShiftfsMark(rootfs string, mounts []configs.ShiftfsMount) error {
	if err := sysboxMgrGrpc.ReqShiftfsMark(mgr.Id, rootfs, mounts); err != nil {
		return fmt.Errorf("failed to request shiftfs marking to sysbox-mgr: %v", err)
	}
	return nil
}

func (mgr *Mgr) Pause() error {
	if err := sysboxMgrGrpc.Pause(mgr.Id); err != nil {
		return fmt.Errorf("failed to notify pause to sysbox-mgr: %v", err)
	}
	return nil
}
