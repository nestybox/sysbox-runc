package libcontainer

import "nestybox/sysvisor-runc/libcontainer/cgroups"
import "nestybox/sysvisor-runc/libcontainer/intelrdt"

type Stats struct {
	Interfaces    []*NetworkInterface
	CgroupStats   *cgroups.Stats
	IntelRdtStats *intelrdt.Stats
}
