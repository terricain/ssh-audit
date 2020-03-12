package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	log "github.com/sirupsen/logrus"
	"github.com/terrycain/ssh-audit/internal/execsnoop"
	"github.com/terrycain/ssh-audit/internal/filewatcher"
	"github.com/terrycain/ssh-audit/internal/poster"
)

func setupSignalHandler(exitChannel chan<- int) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			s := <-signalChan
			switch s {
			case syscall.SIGINT:
				log.Debug("Caught SIGINT")
				exitChannel <- 0
			case syscall.SIGTERM:
				log.Debug("Caught SIGTERM")
				exitChannel <- 0
			}
		}
	}()
}

var CLI struct {
	Debug bool `help:"Enable debug logging"`
	SSHLog string `help:"Log file which contains SSH accepted publickey lines" default:"/var/log/auth.log"`
	EventBuffer int `help:"Event buffer size" default:"5000"`
	DisableBPF bool `help:"Disable eBPF module"`
	URL string `help:"URL to POST JSON events to"`
}

func main() {
	// Deal with commandline flags
	kong.Parse(&CLI)
	fmt.Printf("%#v", &CLI)

	if CLI.Debug {
		log.SetLevel(log.DebugLevel)
	}
	//os.Exit(1)

	log.Info("Starting")
	log.Debug("Setting up signal handlers")
	exitSignal := make(chan int)
	setupSignalHandler(exitSignal)

	// This channel gets json events
	eventChannel := make(chan string, CLI.EventBuffer)

	if CLI.SSHLog != "" {
		log.Info("Starting filewatcher")
		fwatcher := filewatcher.NewFileWatcher()
		fwatcher.Run(CLI.SSHLog, eventChannel)
		defer fwatcher.Close()
	}

	if !CLI.DisableBPF {
		log.Info("Startin execsnooper")
		esnooper := execsnoop.NewExecSnooper()
		esnooper.Run(eventChannel)
		defer esnooper.Close()
	}

	if CLI.URL != "" {
		log.Info("Creating workers")
		workerPool := poster.NewWorkerPool(eventChannel, 0, CLI.URL)
		defer workerPool.Close()
	}

	log.Debug("Waiting for exit signal")
	<-exitSignal
	log.Info("Received exit signal, shutting down")
}
