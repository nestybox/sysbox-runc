// Exposes functions for sysvisor-runc to interact with sysvisor-mgr

package sysvisor

import (
	"fmt"

	"github.com/nestybox/sysvisor-ipc/sysvisorMgrGrpc"
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
	if err := sysvisorMgrGrpc.Register(mgr.Id); err != nil {
		return fmt.Errorf("failed to register with sysvisor-mgr: %v", err)
	}
	return nil
}

func (mgr *Mgr) Unregister() error {
	if err := sysvisorMgrGrpc.Unregister(mgr.Id); err != nil {
		return fmt.Errorf("failed to unregister with sysvisor-mgr: %v", err)
	}
	return nil
}

func (mgr *Mgr) ReqSubid(size uint32) (uint32, uint32, error) {
	uid, gid, err := sysvisorMgrGrpc.SubidAlloc(mgr.Id, uint64(size))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to req subid from sysvisor-mgr: %v", err)
	}
	return uid, gid, nil
}

func (mgr *Mgr) ReqSupMounts(rootfs string, uid, gid uint32, shiftUids bool) ([]specs.Mount, error) {
	mounts, err := sysvisorMgrGrpc.ReqSupMounts(mgr.Id, rootfs, uid, gid, shiftUids)
	if err != nil {
		return []specs.Mount{}, fmt.Errorf("failed to req supplementary mounts from sysvisor-mgr: %v", err)
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
