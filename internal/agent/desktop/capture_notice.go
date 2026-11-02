package desktop

import "fmt"

// setupNoticeFor is the viewer text while a screen-share prompt is open on
// the machine called host.
func setupNoticeFor(host string) string {
	return fmt.Sprintf("Waiting for the person at %s to allow screen sharing", host)
}
