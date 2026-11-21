package agent

import (
	"net"
	"os"
)

// NotifyReady tells systemd (Type=notify) that recovery is done and the
// socket accepts requests. It is a no-op outside systemd.
func NotifyReady() error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	if path[0] == '@' {
		path = "\x00" + path[1:] // abstract namespace
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte("READY=1"))
	return err
}
