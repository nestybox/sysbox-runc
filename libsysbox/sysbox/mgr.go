//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

// Exposes functions for sysbox-runc to interact with sysbox-mgr

package sysbox

import (
	"fmt"

	"github.com/nestybox/sysbox-ipc/sysboxMgrGrpc"
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

func (mgr *Mgr) Register() error {
	if err := sysboxMgrGrpc.Register(mgr.Id); err != nil {
		return fmt.Errorf("failed to register with sysbox-mgr: %v", err)
	}
	return nil
}

func (mgr *Mgr) Unregister() error {
	if err := sysboxMgrGrpc.Unregister(mgr.Id); err != nil {
		return fmt.Errorf("failed to unregister with sysbox-mgr: %v", err)
	}
	return nil
}

func (mgr *Mgr) ReqSubid(size uint32) (uint32, uint32, error) {
	uid, gid, err := sysboxMgrGrpc.SubidAlloc(mgr.Id, uint64(size))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to request subid from sysbox-mgr: %v", err)
	}
	return uid, gid, nil
}

func (mgr *Mgr) ReqDockerStoreMount(rootfs string, uid, gid uint32, shiftUids bool) (specs.Mount, error) {
	m, err := sysboxMgrGrpc.ReqDockerStoreMount(mgr.Id, rootfs, uid, gid, shiftUids)
	if err != nil {
		return specs.Mount{}, fmt.Errorf("failed to request docker-store mount from sysbox-mgr: %v", err)
	}

	specMount := specs.Mount{
		Source:      m.GetSource(),
		Destination: m.GetDest(),
		Type:        m.GetType(),
		Options:     m.GetOpt(),
	}

	return specMount, nil
}

func (mgr *Mgr) PrepDockerStoreMount(path string, uid, gid uint32, shiftUids bool) error {
	if err := sysboxMgrGrpc.PrepDockerStoreMount(mgr.Id, path, uid, gid, shiftUids); err != nil {
		return fmt.Errorf("failed to request docker-store prep from sysbox-mgr: %v", err)
	}
	return nil
}

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
