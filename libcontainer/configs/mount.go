package configs

const (
	// EXT_COPYUP is a directive to copy up the contents of a directory when
	// a tmpfs is mounted over it.
	EXT_COPYUP = 1 << iota
)

type BindSrcInfo struct {
	IsDir bool   `json:"is_dir,omitempty"`
	Uid   uint32 `json:"uid,omitempty"`
	Gid   uint32 `json:"gid,omitempty"`
}

type Mount struct {
	// Source path for the mount.
	Source string `json:"source"`

	// Destination path for the mount inside the container.
	Destination string `json:"destination"`

	// Device the mount is for.
	Device string `json:"device"`

	// Mount flags.
	Flags int `json:"flags"`

	// Propagation Flags
	PropagationFlags []int `json:"propagation_flags"`

	// Mount data applied to the mount.
	Data string `json:"data"`

	// Relabel source if set, "z" indicates shared, "Z" indicates unshared.
	Relabel string `json:"relabel"`

	// Extensions are additional flags that are specific to runc.
	Extensions int `json:"extensions"`

	// Bind mount source info
	BindSrcInfo BindSrcInfo `json:"bind_src_info,omitempty"`

	// Indicates if mounts is to be ID-mapped (see mount_setattr(2) in Linux >= 5.12).
	IDMappedMount bool `json:"idmap_mount"`
}
