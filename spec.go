// +build linux

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libsysbox/syscont"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
)

var specCommand = cli.Command{
	Name:  "spec",
	Usage: "create a new container specification file",
	Description: `The spec command creates the new container specification file
named "` + specConfig + `" for the bundle.

The spec generated is just a starter file. Editing of the spec is required to
achieve desired results.

ID mapping configuration:

Nestybox Sysbox containers use the Linux user namespace and thus require user
and group ID mappings.

The "--id-map" option allows configuration of these mappings for the generated spec.
It's normally not required, unless the user wants to control the user and group IDs
mappings of the container.

If the "--id-map" option is omitted, the generated spec will not include the
user and group ID mappings. In this case sysbox-runc will automatically
allocate them when the container is created. The allocation is done in such as
way as to provide each sys container an exclusive range of uid(gid)s on the
host, as a means to improve isolation. This feature requires that the
container's root filesystem be owned by "root:root".

If the "--id-map" option is given, the generated spec will include them and
sysbox-runc will honor them when creating the container. They are expected
to match the container's root filesystem ownership. Note that the size of the
range is required be >= ` + strconv.FormatUint(uint64(syscont.IdRangeMin), 10) + ` (for compatibility with Linux distros
that use ID 65534 as "nobody").
`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "bundle, b",
			Value: "",
			Usage: "path to the sys container's bundle directory",
		},
		cli.StringFlag{
			Name:  "id-map, m",
			Value: "",
			Usage: `"uid gid size" ID mappings (see description above)`,
		},
	},
	Action: func(context *cli.Context) error {
		var uid, gid, size uint32

		idMap := context.String("id-map")
		if idMap != "" {
			if err := parseIDMap(idMap, &uid, &gid, &size); err != nil {
				return err
			}
		}

		spec, err := syscont.Example()
		if err != nil {
			return err
		}

		if idMap != "" {
			spec.Linux.UIDMappings = []specs.LinuxIDMapping{{
				HostID:      uid,
				ContainerID: 0,
				Size:        size,
			}}
			spec.Linux.GIDMappings = []specs.LinuxIDMapping{{
				HostID:      gid,
				ContainerID: 0,
				Size:        size,
			}}
		}

		bundle := context.String("bundle")
		if bundle != "" {
			if err := os.Chdir(bundle); err != nil {
				return err
			}
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

// parseIDMap parses the id-map flag and returns the uid, gid, and size
func parseIDMap(idMap string, uid, gid, size *uint32) error {
	var num [3]uint64
	var err error

	fields := strings.Fields(idMap)
	if len(fields) != 3 {
		return fmt.Errorf("id-map must be of the form \"uid gid size\"; got %v", idMap)
	}

	for i, f := range fields {
		num[i], err = strconv.ParseUint(f, 10, 32)
		if err != nil {
			return err
		}
	}

	*uid = uint32(num[0])
	*gid = uint32(num[1])
	*size = uint32(num[2])

	if *uid > math.MaxUint32 || *gid > math.MaxUint32 || *size < syscont.IdRangeMin {
		return fmt.Errorf("invalid id-map \"%v\": uid and gid must be <= %v, size must be >= %v",
			idMap, math.MaxUint32, syscont.IdRangeMin)
	}

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
