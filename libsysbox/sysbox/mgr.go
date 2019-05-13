package sysbox

// TODO: refactor uid alloc to remove the 'id' parameter; not needed and undesired for session-less server.

import (
	"github.com/nestybox/sysbox-ipc/sysboxMgrGrpc"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// subidAlloc stores subuid(gid) allocated from sysbox-mgr
type subidAlloc struct {
	Valid bool
	Id    string
	Uid   uint32
	Gid   uint32
}

// Mgr represents the sysbox-mgr within sysbox-runc
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

	u, g, err := sysboxMgrGrpc.SubidAlloc(id, uint64(size))
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

	return nil
}
