package sysvisor

// TODO: refactor uid alloc to remove the 'id' parameter; not needed and undesired for session-less server.

import (
	"github.com/nestybox/sysvisor/sysvisor-ipc/sysvisorMgrGrpc"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// subidAlloc stores subuid(gid) allocated from sysvisor-mgr
type subidAlloc struct {
	Valid bool
	Id    string
	Uid   uint32
	Gid   uint32
}

// Mgr represents the sysvisor-mgr within sysvisor-runc
type Mgr struct {
	Active    bool
	Subid     subidAlloc
	SupMounts []specs.Mount
}

func NewMgr(enable bool) *Mgr {
	return &Mgr{
		Active: enable,
	}
}

func (mgr *Mgr) Enabled() bool {
	return mgr.Active
}

func (mgr *Mgr) ReqSubid(id string, size uint32) (uint32, uint32, error) {

	u, g, err := sysvisorMgrGrpc.SubidAlloc(id, uint64(size))
	if err != nil {
		return 0, 0, err
	}

	mgr.Subid = subidAlloc{
		Valid: true,
		Id:    id,
		Uid:   u,
		Gid:   g,
	}

	return u, g, nil
}

func (mgr *Mgr) ReqSupMounts() ([]specs.Mount, error) {

	// TODO: write me up

	return []specs.Mount{}, nil
}

func (mgr *Mgr) RelResources() error {

	// TODO: write me up

	// TODO: modify the SubidFree such that it's passed the allocated uid(gid), rather than
	// container id

	if mgr.Subid.Valid {
		if err := sysvisorMgrGrpc.SubidFree(mgr.Subid.Id); err != nil {
			return err
		}
		mgr.Subid.Valid = false
	}

	// if len(mgr.supMounts) > 0 {
	// 	if err := sysvisorMgrGrpc.relSubMounts(c.id, mgr.supMounts); err != nil {
	// 		return err
	// 	}
	// }

	return nil
}
