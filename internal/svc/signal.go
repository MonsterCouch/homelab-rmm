package svc

import (
	"os"
	"os/signal"
	"syscall"
)

func interrupt() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	return ch
}
