package sysvisor

import (
	"github.com/nestybox/sysvisor-ipc/sysvisorMgrGrpc"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// Mgr is an object that encapsulates interactions with the sysvisor-mgr when creating or
// destroying a container
type Mgr struct {
	Active       bool
	Id           string // container-id
	GotSubid     bool   // indicates if subids were obtained from sysvisor-mgr
	GotSupMounts bool   // indicates if supplemental mounts were obtained from sysvisor-mgr
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

func (mgr *Mgr) ReqSubid(size uint32) (uint32, uint32, error) {
	u, g, err := sysvisorMgrGrpc.SubidAlloc(mgr.Id, uint64(size))
	if err != nil {
		return 0, 0, err
	}
	mgr.GotSubid = true
	return u, g, nil
}

func (mgr *Mgr) ReqSupMounts(rootfs string, uid, gid uint32, shiftUids bool) ([]specs.Mount, error) {
	mounts, err := sysvisorMgrGrpc.ReqSupMounts(mgr.Id, rootfs, uid, gid, shiftUids)
	if err != nil {
		return []specs.Mount{}, err
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

	mgr.GotSupMounts = true
	return specMounts, nil
}

// RelResources releases resources obtained from sysvisor-mgr
func (mgr *Mgr) RelResources() error {
	if mgr.GotSubid {
		if err := sysvisorMgrGrpc.SubidFree(mgr.Id); err != nil {
			return err
		}
		mgr.GotSubid = false
	}

	if mgr.GotSupMounts {
		if err := sysvisorMgrGrpc.RelSupMounts(mgr.Id); err != nil {
			return err
		}
		mgr.GotSupMounts = false
	}

	return nil
}
