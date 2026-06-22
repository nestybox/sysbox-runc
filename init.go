package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/logs"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()

		level := os.Getenv("_LIBCONTAINER_LOGLEVEL")
		logLevel, err := logrus.ParseLevel(level)
		if err != nil {
			panic(fmt.Sprintf("libcontainer: failed to parse log level: %q: %v", level, err))
		}

		err = logs.ConfigureLogging(logs.Config{
			LogPipeFd: os.Getenv("_LIBCONTAINER_LOGPIPE"),
			LogFormat: "json",
			LogLevel:  logLevel,
		})
		if err != nil {
			panic(fmt.Sprintf("libcontainer: failed to configure logging: %v", err))
		}
		logrus.Debug("child process in init()")
	}
}

var initCommand = cli.Command{
	Name:  "init",
	Usage: `initialize the namespaces and launch the process (do not call it outside of sysbox-runc)`,
	Action: func(context *cli.Context) error {
		initType := os.Getenv("_LIBCONTAINER_INITTYPE")

		factory, _ := libcontainer.New("")
		if err := factory.StartInitialization(); err != nil {
			os.Exit(1)
		}

		// initMount helpers return here without exec; that's normal.
		if initType == "mount" {
			os.Exit(0)
		}

		panic("libcontainer: container init failed to exec")
	},
}
