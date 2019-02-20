package libcontainer

import "nestybox/syscont-runc/libcontainer/cgroups"
import "nestybox/syscont-runc/libcontainer/intelrdt"

type Stats struct {
	Interfaces    []*NetworkInterface
	CgroupStats   *cgroups.Stats
	IntelRdtStats *intelrdt.Stats
}
