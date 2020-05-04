// +build linux

package main

import (
	"os"

	"github.com/opencontainers/runc/libsysbox/sysbox"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

// default action is to start a container
var runCommand = cli.Command{
	Name:  "run",
	Usage: "create and run a system container",
	ArgsUsage: `<container-id>

Where "<container-id>" is your name for the instance of the container that you
are starting. The name you provide for the container instance must be unique on
your host.`,
	Description: `The run command creates an instance of a container for a bundle. The bundle
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
		cli.BoolFlag{
			Name:  "detach, d",
			Usage: "detach from the container's process",
		},
		cli.StringFlag{
			Name:  "pid-file",
			Value: "",
			Usage: "specify the file to write the process id to",
		},
		cli.BoolFlag{
			Name:  "no-subreaper",
			Usage: "disable the use of the subreaper used to reap reparented processes",
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
			err       error
			spec      *specs.Spec
			shiftUids bool
			status    int
			profiler  interface{ Stop() }
		)

		// Enable profiler if requested to do so
		profiler, err = runProfiler(context)
		if err != nil {
			return err
		}

		defer func() {
			if profiler != nil {
				logrus.Info("Stopping profiler ...")
				profiler.Stop()
			}
		}()

		if err = checkArgs(context, 1, exactArgs); err != nil {
			return err
		}
		if err = revisePidFile(context); err != nil {
			return err
		}

		id := context.Args().First()

		sysMgr := sysbox.NewMgr(id, !context.GlobalBool("no-sysbox-mgr"))
		sysFs := sysbox.NewFs(id, !context.GlobalBool("no-sysbox-fs"))

		// register with sysMgr
		if sysMgr.Enabled() {
			if err = sysMgr.Register(); err != nil {
				return err
			}
			defer func() {
				if err != nil {
					sysMgr.Unregister()
				}
			}()
		}

		spec, shiftUids, err = setupSpec(context, sysMgr, sysFs)
		if err != nil {
			return err
		}

		if err = sysbox.CheckHostConfig(context, shiftUids); err != nil {
			return err
		}

		// pre-register with sysFs
		if sysFs.Enabled() {
			if err = sysFs.PreRegister(); err != nil {
				return err
			}
			defer func() {
				if err != nil {
					sysFs.Unregister()
				}
			}()
		}

		status, err = startContainer(context, spec, CT_ACT_RUN, nil, shiftUids, sysMgr, sysFs)
		if err == nil {

			// note: defer func() to stop profiler won't execute on os.Exit(); must explicitly stop it.
			if profiler != nil {
				logrus.Info("Stopping profiler ...")
				profiler.Stop()
			}

			// exit with the container's exit status so any external supervisor is
			// notified of the exit with the correct exit status.
			os.Exit(status)
		}

		return err
	},
}
