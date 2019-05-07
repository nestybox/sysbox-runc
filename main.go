//
// (c) 2019 Nestybox. All Rights Reserved.
//

//
// Change Log:
//
// * Modified usage message for sysvisor-runc.
//

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

// version will be populated by the Makefile, read from
// VERSION file of the source code.
var version = ""

// gitCommit will be the hash that the binary was built from
// and will be populated by the Makefile
var gitCommit = ""

const (
	specConfig = "config.json"
	usage      = `system container runc

sysvisor-runc is a command line client for running system containers.

A system container is a container whose main purpose is to package and
deploy a full operating system environment (e.g., init process, system
daemons, libraries, utilities, etc.)

A system container provides enviroment inside of which application
containers can be deployed (e.g., by running Docker and Kubernetes
inside the system container).

sysvisor-runc is a fork of the Open Container Initiative (OCI) runc
that has been customized for system containers.

sysvisor-runc is configured using OCI bundles (i.e., a directory that
includes a specification file named "` + specConfig + `" and a root
filesystem containing the contents of the system container).

System containers must be isolated from the host and from each other.
sysvisor-runc achieves this by using several Linux isolation
technologies (e.g., all Linux namespaces, cgroups, seccomp, etc.) as
well as by restricting the set of configurations for a system
container (i.e., the system container OCI bundle must meet certain
requirements). sysvisor-runc will check that the config meets these
requirements when creating a system container; the "sysvisor-runc spec"
command can be used to generate a baseline system container configuration.

To start a new instance of a system container:

    # sysvisor-runc run [ -b bundle ] <container-id>

Where "<container-id>" is your name for the instance of the system
container that you are starting (which must be unique on the host).
`
)

func main() {
	app := cli.NewApp()
	app.Name = "sysvisor-runc"
	app.Usage = usage

	var v []string
	if version != "" {
		v = append(v, version)
	}
	if gitCommit != "" {
		v = append(v, fmt.Sprintf("commit: %s", gitCommit))
	}
	v = append(v, fmt.Sprintf("spec: %s", specs.Version))
	app.Version = strings.Join(v, "\n")

	root := "/run/sysvisor-runc"
	if shouldHonorXDGRuntimeDir() {
		if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
			root = runtimeDir + "/sysvisor-runc"
			// According to the XDG specification, we need to set anything in
			// XDG_RUNTIME_DIR to have a sticky bit if we don't want it to get
			// auto-pruned.
			if err := os.MkdirAll(root, 0700); err != nil {
				fatal(err)
			}
			if err := os.Chmod(root, 0700|os.ModeSticky); err != nil {
				fatal(err)
			}
		}
	}

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug",
			Usage: "enable debug output for logging",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "/dev/null",
			Usage: "set the log file path where internal debug information is written",
		},
		cli.StringFlag{
			Name:  "log-format",
			Value: "text",
			Usage: "set the format used by logs ('text' (default), or 'json')",
		},
		cli.StringFlag{
			Name:  "root",
			Value: root,
			Usage: "root directory for storage of container state (this should be located in tmpfs)",
		},
		cli.StringFlag{
			Name:  "criu",
			Value: "criu",
			Usage: "path to the criu binary used for checkpoint and restore",
		},
		cli.BoolFlag{
			Name:  "systemd-cgroup",
			Usage: "enable systemd cgroup support, expects cgroupsPath to be of form \"slice:prefix:name\" for e.g. \"system.slice:sysvisor-runc:434234\"",
		},
		cli.StringFlag{
			Name:  "rootless",
			Value: "auto",
			Usage: "ignore cgroup permission errors ('true', 'false', or 'auto')",
		},
		cli.BoolFlag{
			Name:  "no-sysvisor-fs",
			Usage: "do not interact with sysvisor-fs; meant for testing and debugging.",
		},
		cli.BoolFlag{
			Name:  "no-sysvisor-mgr",
			Usage: "do not interact with sysvisor-mgr; meant for testing and debugging.",
		},
		cli.BoolFlag{
			Name:  "no-kernel-check",
			Usage: "do not check kernel compatibility; meant for testing and debugging.",
		},
	}
	app.Commands = []cli.Command{
		checkpointCommand,
		createCommand,
		deleteCommand,
		eventsCommand,
		execCommand,
		initCommand,
		killCommand,
		listCommand,
		pauseCommand,
		psCommand,
		restoreCommand,
		resumeCommand,
		runCommand,
		specCommand,
		startCommand,
		stateCommand,
		updateCommand,
	}
	app.Before = func(context *cli.Context) error {
		if context.GlobalBool("debug") {
			logrus.SetLevel(logrus.DebugLevel)
		}
		if path := context.GlobalString("log"); path != "" {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0666)
			if err != nil {
				return err
			}
			logrus.SetOutput(f)
		}
		switch context.GlobalString("log-format") {
		case "text":
			// retain logrus's default.
		case "json":
			logrus.SetFormatter(new(logrus.JSONFormatter))
		default:
			return fmt.Errorf("unknown log-format %q", context.GlobalString("log-format"))
		}
		return nil
	}
	// If the command returns an error, cli takes upon itself to print
	// the error on cli.ErrWriter and exit.
	// Use our own writer here to ensure the log gets sent to the right location.
	cli.ErrWriter = &FatalWriter{cli.ErrWriter}
	if err := app.Run(os.Args); err != nil {
		fatal(err)
	}
}

type FatalWriter struct {
	cliErrWriter io.Writer
}

func (f *FatalWriter) Write(p []byte) (n int, err error) {
	logrus.Error(string(p))
	return f.cliErrWriter.Write(p)
}
