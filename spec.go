// +build linux

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"syscall"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libsyscontainer/syscontSpec"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
)

var specCommand = cli.Command{
	Name:      "spec",
	Usage:     "create a new system container specification file",
	ArgsUsage: "<uid> <gid> <size>",
	Description: `The spec command creates the new system container specification file
named "` + specConfig + `" for the bundle.

The spec generated is just a starter file. Editing of the spec is required to
achieve desired results.

System containers always use the Linux user namespace and thus require user and
group id mappings.

Arguments uid and gid indicate the host user/group IDs to which the system
container's root user/group are mapped. Size is the number of IDs that must be
mapped; it must be set >= ` + strconv.FormatUint(uint64(syscontSpec.IdRangeMin),10) + ` for compatibility
with Linux distros that use id 65534 as "nobody".

If the "--bundle" option is present, the uid and gid parameters must match the
user and group owners of the bundle.

When starting a container through sysvisor-runc, sysvisor-runc needs root
privilege. If not already running as root, you can use sudo to give
sysvisor-runc root privilege.

sysvisor-runc does not currently support running without root privilege (i.e.,
rootless).
`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "bundle, b",
			Value: "",
			Usage: "path to the root of the bundle directory (i.e., rootfs)",
		},
	},
	Action: func(context *cli.Context) error {

		var uid, gid, size uint32

		if err := checkArgs(context, 3, exactArgs); err != nil {
			return err
		}

		if err := getArgs(context, &uid, &gid, &size); err != nil {
			return err
		}

		checkNoFile := func(name string) error {
			_, err := os.Stat(name)
			if err == nil {
				return fmt.Errorf("File %s exists. Remove it first", name)
			}
			if !os.IsNotExist(err) {
				return err
			}
			return nil
		}

		bundle := context.String("bundle")

		if bundle != "" {
			fi, err := os.Stat(bundle)
			if err != nil {
				return err
			}
			if bundleId := fi.Sys().(*syscall.Stat_t).Uid; uid != bundleId {
				return fmt.Errorf("rootfs uid %d does not match uid %d passed to this command", bundleId, uid)
			}
			if bundleId := fi.Sys().(*syscall.Stat_t).Gid; gid != bundleId {
				return fmt.Errorf("rootfs gid %d does not match gid %d passed to this command", bundleId, gid)
			}
		}

		spec, err := syscontSpec.Example(uid, gid, size, bundle)
		if err != nil {
			return err
		}

		if err := syscontSpec.ConvertSpec(spec, false); err != nil {
			return err
		}

		if bundle != "" {
			if err := os.Chdir(bundle); err != nil {
				return err
			}
		}

		if err := checkNoFile(specConfig); err != nil {
			return err
		}

		data, err := json.MarshalIndent(spec, "", "\t")
		if err != nil {
			return err
		}
		return ioutil.WriteFile(specConfig, data, 0666)
	},
}

// getArgs parses and returns the uid, gid, and size command line arguments
func getArgs (context *cli.Context, uid, gid, size *uint32) error {
	var num [3]uint64
	var err error

	for i :=0; i < 3; i++ {
		str := context.Args().Get(i)
		num[i], err = strconv.ParseUint(str, 10, 32)
		if err != nil {
			return err
		}
	}

	// TODO: check validity of uid, gid, and size
	// (must be < 2^32, must be in /etc/subuid|gid and size must match)

	*uid = uint32(num[0])
	*gid = uint32(num[1])
	*size = uint32(num[2])

	return nil
}

// loadSpec loads the specification from the provided path
func loadSpec(cPath string) (spec *specs.Spec, err error) {
	cf, err := os.Open(cPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("JSON specification file %s not found", cPath)
		}
		return nil, err
	}
	defer cf.Close()

	if err = json.NewDecoder(cf).Decode(&spec); err != nil {
		return nil, err
	}

	return spec, validateProcessSpec(spec.Process)
}

func createLibContainerRlimit(rlimit specs.POSIXRlimit) (configs.Rlimit, error) {
	rl, err := strToRlimit(rlimit.Type)
	if err != nil {
		return configs.Rlimit{}, err
	}
	return configs.Rlimit{
		Type: rl,
		Hard: rlimit.Hard,
		Soft: rlimit.Soft,
	}, nil
}
