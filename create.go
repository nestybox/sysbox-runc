package main

import (
	"fmt"
	"os"

	"github.com/opencontainers/runc/libsysbox/sysbox"
	"github.com/opencontainers/runc/libsysbox/syscont"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
)

var createCommand = cli.Command{
	Name:  "create",
	Usage: "create a system container",
	ArgsUsage: `<container-id>

Where "<container-id>" is your name for the instance of the system container that you
are starting. The name you provide for the container instance must be unique on
your host.`,
	Description: `The create command creates an instance of a system container for a bundle. The bundle
is a directory with a specification file named "` + specConfig + `" and a root
filesystem.

The specification file includes an args parameter. The args parameter is used
to specify command(s) that get run when the container is started. To change the
command(s) that get executed on start, edit the args parameter of the spec. See
"runc spec --help" for more explanation.`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "bundle, b",
			Value: "",
			Usage: `path to the root of the bundle directory, defaults to the current directory`,
		},
		cli.StringFlag{
			Name:  "console-socket",
			Value: "",
			Usage: "path to an AF_UNIX socket which will receive a file descriptor referencing the master end of the console's pseudoterminal",
		},
		cli.StringFlag{
			Name:  "pid-file",
			Value: "",
			Usage: "specify the file to write the process id to",
		},
		cli.BoolFlag{
			Name:  "no-pivot",
			Usage: "do not use pivot root to jail process inside rootfs.  This should be used whenever the rootfs is on top of a ramdisk",
		},
		cli.BoolFlag{
			Name:  "no-new-keyring",
			Usage: "do not create a new session keyring for the container.  This will cause the container to inherit the calling processes session key",
		},
		cli.IntFlag{
			Name:  "preserve-fds",
			Usage: "Pass N additional file descriptors to the container (stdio + $LISTEN_FDS + N in total)",
		},
	},
	Action: func(context *cli.Context) error {
		var (
			err    error
			spec   *specs.Spec
			status int
		)

		if err = checkArgs(context, 1, exactArgs); err != nil {
			return err
		}
		if err = revisePidFile(context); err != nil {
			return err
		}

		spec, err = setupSpec(context)
		if err != nil {
			return err
		}

		if err = sysbox.CheckHostConfig(context, spec); err != nil {
			return err
		}

		id := context.Args().First()

		withMgr := !context.GlobalBool("no-sysbox-mgr")
		withFs := !context.GlobalBool("no-sysbox-fs")

		sysbox := sysbox.NewSysbox(id, withMgr, withFs)

		// register with sysMgr
		if sysbox.Mgr.Enabled() {
			if err = sysbox.Mgr.Register(spec); err != nil {
				return err
			}
			defer func() {
				if err != nil {
					sysbox.Mgr.Unregister()
				}
			}()
		}

		// Get sysbox-fs related configs
		if sysbox.Fs.Enabled() {
			if err = sysbox.Fs.GetConfig(); err != nil {
				return err
			}
		}

		if err = syscont.ConvertSpec(context, spec, sysbox); err != nil {
			return fmt.Errorf("error in the container spec: %v", err)
		}

		// pre-register with sysFs
		if sysbox.Fs.Enabled() {
			if err = sysbox.Fs.PreRegister(spec.Linux.Namespaces); err != nil {
				return err
			}
			defer func() {
				if err != nil {
					sysbox.Fs.Unregister()
				}
			}()
		}

		status, err = startContainer(context, spec, CT_ACT_CREATE, nil, sysbox)
		if err != nil {
			return err
		}
		// exit with the container's exit status so any external supervisor is
		// notified of the exit with the correct exit status.
		os.Exit(status)
		return nil
	},
}
