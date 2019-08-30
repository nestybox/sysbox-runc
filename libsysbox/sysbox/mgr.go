//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

// Exposes functions for sysbox-runc to interact with sysbox-mgr

package sysbox

import (
	"fmt"

	"github.com/nestybox/sysbox-ipc/sysboxMgrGrpc"
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
		return 0, 0, fmt.Errorf("failed to req subid from sysbox-mgr: %v", err)
	}
	return uid, gid, nil
}

func (mgr *Mgr) ReqSupMounts(rootfs string, uid, gid uint32, shiftUids bool) ([]specs.Mount, error) {
	mounts, err := sysboxMgrGrpc.ReqSupMounts(mgr.Id, rootfs, uid, gid, shiftUids)
	if err != nil {
		return []specs.Mount{}, fmt.Errorf("failed to req supplementary mounts from sysbox-mgr: %v", err)
	}

	// convert mounts to []spec.Mount
	specMounts := []specs.Mount{}
	for _, m := range mounts {
		specMount := specs.Mount{
			Source:      m.GetSource(),
			Destination: m.GetDest(),
			Type:        m.GetType(),
			Options:     m.GetOpt(),
		}
		specMounts = append(specMounts, specMount)
	}

	return specMounts, nil
}
