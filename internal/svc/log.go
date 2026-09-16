package svc

import (
	"io"
	"os"
)

// LogWriter combines the sinks a process logs to so that one dead sink cannot
// silence the others.
//
// A process the Windows Service Control Manager starts inherits no standard
// handles at all: GetStdHandle(STD_ERROR_HANDLE) hands back 0, and every write
// to os.Stderr fails with "The handle is invalid". io.MultiWriter returns on
// the first sink that errors and never reaches the ones behind it, and slog
// throws its handler's write error away - so agent.log, listed second behind
// os.Stderr, was created by every Windows service install and then never
// written to, and neither the log file nor stderr had a word to say about it.
//
// Two defences, because either alone still loses lines. Sinks that cannot be
// written to at all are dropped here, before the handler is built, so the
// common case is a plain file with no wrapper. A sink that only starts failing
// later - stderr redirected to a pipe whose reader went away, a full disk -
// costs its own copy of the line and nothing more: the write still succeeds as
// long as one sink took it.
func LogWriter(sinks ...io.Writer) io.Writer {
	live := make([]io.Writer, 0, len(sinks))
	for _, w := range sinks {
		if usableSink(w) {
			live = append(live, w)
		}
	}
	switch len(live) {
	case 0:
		return io.Discard
	case 1:
		return live[0]
	default:
		return bestEffort(live)
	}
}

// usableSink reports whether w is worth handing to the log handler. Only
// *os.File is examined: Stat on a handle the service manager never gave us
// fails (GetFileType on handle 0 is ERROR_INVALID_HANDLE), which asks "is this
// stream connected to anything?" without writing a probe byte into somebody's
// console. Anything else - a buffer, a pipe, a test double - is taken on
// trust; bestEffort covers it if it turns out to be wrong.
func usableSink(w io.Writer) bool {
	if w == nil {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return true
	}
	_, err := f.Stat() // a nil *os.File answers ErrInvalid here
	return err == nil
}

// bestEffort is io.MultiWriter without the short circuit: every sink is
// offered every record, and the write counts as a success if any of them took
// it. The error of the first sink that refused is kept for the caller that
// looks, which slog is not.
type bestEffort []io.Writer

func (b bestEffort) Write(p []byte) (int, error) {
	var firstErr error
	wrote := false
	for _, w := range b {
		if _, err := w.Write(p); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		wrote = true
	}
	if wrote {
		return len(p), nil
	}
	return 0, firstErr
}
