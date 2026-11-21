package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

// Listen creates the Unix socket with mode 0660 owned by root:group so
// only members of group (efw-web's service group) can connect. An empty
// group keeps the current group (tests).
func Listen(path, group string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		os.Remove(path) // stale socket from a previous run
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			ln.Close()
			return nil, err
		}
		gid, _ := strconv.Atoi(g.Gid)
		if err := os.Chown(path, 0, gid); err != nil {
			ln.Close()
			return nil, err
		}
	}
	return ln, nil
}

// Serve accepts connections until ctx is cancelled.
func (a *Agent) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go a.serveConn(ctx, c)
	}
}

func (a *Agent) serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	peer := peerName(c)
	req, err := DecodeRequest(c)
	var resp Response
	if err != nil {
		resp = fail(CodeBadRequest, err.Error())
		a.defaults()
		a.Log.Warn("rejected request", "peer", peer, "err", err)
	} else {
		resp = a.Handle(ctx, req, peer)
	}
	_ = json.NewEncoder(c).Encode(resp)
}
