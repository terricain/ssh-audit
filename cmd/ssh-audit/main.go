package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/terrycain/ssh-audit/internal/execsnoop"
	"github.com/terrycain/ssh-audit/internal/filewatcher"
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

func main() {
	log.SetLevel(log.DebugLevel)
	log.Info("Starting")

	log.Debug("Setting up signal handlers")
	exitSignal := make(chan int)
	setupSignalHandler(exitSignal)

	// This channel gets json events
	eventChannel := make(chan string, 1000)

	log.Info("Starting filewatcher")
	fwatcher := filewatcher.NewFileWatcher()
	fwatcher.Run("/var/log/auth.log", eventChannel)
	defer fwatcher.Close()

	log.Info("Startin execsnooper")
	esnooper := execsnoop.NewExecSnooper()
	esnooper.Run(eventChannel)
	defer esnooper.Close()

	log.Debug("Waiting for exit signal")
	<-exitSignal
	log.Info("Received exit signal, shutting down")
}
