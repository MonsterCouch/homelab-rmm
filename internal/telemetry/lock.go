package telemetry

import "errors"

// ErrDataDirBusy means another process holds the data directory lock.
var ErrDataDirBusy = errors.New("another process is using this data directory; stop the server first")
