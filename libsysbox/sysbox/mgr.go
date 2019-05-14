package sysbox

import (
	"github.com/nestybox/sysbox-ipc/sysboxMgrGrpc"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// Mgr is an object that encapsulates interactions with the sysbox-mgr when creating or
// destroying a container
type Mgr struct {
	Active       bool
	Id           string // container-id
	GotSubid     bool   // indicates if subids were obtained from sysbox-mgr
	GotSupMounts bool   // indicates if supplemental mounts were obtained from sysbox-mgr
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
	u, g, err := sysboxMgrGrpc.SubidAlloc(mgr.Id, uint64(size))
	if err != nil {
		return 0, 0, err
	}
	mgr.GotSubid = true
	return u, g, nil
}

func (mgr *Mgr) ReqSupMounts(rootfs string, uid, gid uint32, shiftUids bool) ([]specs.Mount, error) {
	// TODO: implement this function
	return nil, nil
}

// RelResources releases resources obtained from sysbox-mgr
func (mgr *Mgr) RelResources() error {
	// TODO: implement this function
	return nil
}
