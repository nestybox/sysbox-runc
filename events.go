// +build linux

package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/opencontainers/runc/libcontainer"
)

// event struct for encoding the event data to json.
type event struct {
	Type string      `json:"type"`
	ID   string      `json:"id"`
	Data interface{} `json:"data,omitempty"`
}

var eventsCommand = cli.Command{
	Name:  "events",
	Usage: "display container events such as OOM notifications, cpu, memory, IO and network stats",
	ArgsUsage: `<container-id>

Where "<container-id>" is the name for the instance of the container.`,
	Description: `The events command displays information about the container. By default the
information is displayed once every 5 seconds.`,
	Flags: []cli.Flag{
		cli.DurationFlag{Name: "interval", Value: 5 * time.Second, Usage: "set the stats collection interval"},
		cli.BoolFlag{Name: "stats", Usage: "display the container's stats then exit"},
	},
	Action: func(context *cli.Context) {
		container, err := getContainer(context)
		if err != nil {
			fatal(err)
		}
		id := context.Args().First()
		status, err := container.Status()
		if err != nil {
			fatal(err)
		}
		if status == libcontainer.Destroyed {
			fatalf("container with id %s is not running",id)
		}
		var (
			stats  = make(chan *libcontainer.Stats, 1)
			events = make(chan *event, 1024)
			group  = &sync.WaitGroup{}
		)
		group.Add(1)
		go func() {
			defer group.Done()
			enc := json.NewEncoder(os.Stdout)
			for e := range events {
				if err := enc.Encode(e); err != nil {
					logrus.Error(err)
				}
			}
		}()
		if context.Bool("stats") {
			s, err := container.Stats()
			if err != nil {
				fatal(err)
			}
			events <- &event{Type: "stats", ID: container.ID(), Data: s}
			close(events)
			group.Wait()
			return
		}
		go func() {
			for range time.Tick(context.Duration("interval")) {
				s, err := container.Stats()
				if err != nil {
					logrus.Error(err)
					continue
				}
				stats <- s
			}
		}()
		n, err := container.NotifyOOM()
		if err != nil {
			fatal(err)
		}
		for {
			select {
			case _, ok := <-n:
				if ok {
					// this means an oom event was received, if it is !ok then
					// the channel was closed because the container stopped and
					// the cgroups no longer exist.
					events <- &event{Type: "oom", ID: container.ID()}
				} else {
					n = nil
				}
			case s := <-stats:
				events <- &event{Type: "stats", ID: container.ID(), Data: s}
			}
			if n == nil {
				close(events)
				break
			}
		}
		group.Wait()
	},
}
