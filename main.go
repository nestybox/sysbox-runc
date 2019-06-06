//
// (c) 2019 Nestybox. All Rights Reserved.
//

package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/opencontainers/runc/libcontainer/logs"
	"github.com/opencontainers/runc/libcontainer/seccomp"
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
	usage      = `sysbox container runtime runc

sysbox-runc is a command line client for running system containers.

A system container is a container whose main purpose is to package and
deploy a full operating system environment (e.g., init process, system
daemons, libraries, utilities, etc.)

A system container provides enviroment inside of which application
containers can be deployed (e.g., by running Docker and Kubernetes
inside the system container).

sysbox-runc is a fork of the Open Container Initiative (OCI) runc
that has been customized for system containers.

sysbox-runc is configured using OCI bundles (i.e., a directory that
includes a specification file named "` + specConfig + `" and a root
filesystem containing the contents of the system container).

System containers must be isolated from the host and from each other.
sysbox-runc achieves this by using several Linux isolation
technologies (e.g., all Linux namespaces, cgroups, seccomp, etc.) as
well as by restricting the set of configurations for a system
container (i.e., the system container OCI bundle must meet certain
requirements). sysbox-runc will check that the config meets these
requirements when creating a system container; the "sysbox-runc spec"
command can be used to generate a baseline system container configuration.

To start a new instance of a system container:

    # sysbox-runc run [ -b bundle ] <container-id>

Where "<container-id>" is your name for the instance of the system
container that you are starting (which must be unique on the host).
`
)

func main() {
	app := cli.NewApp()
	app.Name = "sysbox-runc"
	app.Usage = usage

	var v []string
	if version != "" {
		v = append(v, version)
	}
	if gitCommit != "" {
		v = append(v, "commit: "+gitCommit)
	}
	v = append(v, "spec: "+specs.Version)
	v = append(v, "go: "+runtime.Version())
	if seccomp.IsEnabled() {
		major, minor, micro := seccomp.Version()
		v = append(v, fmt.Sprintf("libseccomp: %d.%d.%d", major, minor, micro))
	}
	app.Version = strings.Join(v, "\n")

	xdgRuntimeDir := ""
	root := "/run/sysbox-runc"
	if shouldHonorXDGRuntimeDir() {
		if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
			root = runtimeDir + "/sysbox-runc"
			xdgRuntimeDir = root
		}
	}

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug",
			Usage: "enable debug output for logging",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "",
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
		cli.BoolFlag{
			Name:  "no-sysbox-fs",
			Usage: "do not interact with sysbox-fs; meant for testing and debugging.",
		},
		cli.BoolFlag{
			Name:  "no-sysbox-mgr",
			Usage: "do not interact with sysbox-mgr; meant for testing and debugging.",
		},
		cli.BoolFlag{
			Name:  "no-kernel-check",
			Usage: "do not check kernel compatibility; meant for testing and debugging.",
		},
	}
	app.Commands = []cli.Command{
		createCommand,
		deleteCommand,
		eventsCommand,
		execCommand,
		initCommand,
		killCommand,
		listCommand,
		pauseCommand,
		psCommand,
		resumeCommand,
		runCommand,
		specCommand,
		startCommand,
		stateCommand,
		updateCommand,
	}
	app.Before = func(context *cli.Context) error {
		if !context.IsSet("root") && xdgRuntimeDir != "" {
			// According to the XDG specification, we need to set anything in
			// XDG_RUNTIME_DIR to have a sticky bit if we don't want it to get
			// auto-pruned.
			if err := os.MkdirAll(root, 0700); err != nil {
				fmt.Fprintln(os.Stderr, "the path in $XDG_RUNTIME_DIR must be writable by the user")
				fatal(err)
			}
			if err := os.Chmod(root, 0700|os.ModeSticky); err != nil {
				fmt.Fprintln(os.Stderr, "you should check permission of the path in $XDG_RUNTIME_DIR")
				fatal(err)
			}
		}
		if err := reviseRootDir(context); err != nil {
			return err
		}
		return logs.ConfigureLogging(createLogConfig(context))
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
	if !logrusToStderr() {
		return f.cliErrWriter.Write(p)
	}
	return len(p), nil
}

func createLogConfig(context *cli.Context) logs.Config {
	logFilePath := context.GlobalString("log")
	logPipeFd := ""
	if logFilePath == "" {
		logPipeFd = "2"
	}
	config := logs.Config{
		LogPipeFd:   logPipeFd,
		LogLevel:    logrus.InfoLevel,
		LogFilePath: logFilePath,
		LogFormat:   context.GlobalString("log-format"),
	}
	if context.GlobalBool("debug") {
		config.LogLevel = logrus.DebugLevel
	}

	return config
}
