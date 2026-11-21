//go:build linux

package agent

import (
	"fmt"
	"net"
	"syscall"
)

// peerName identifies the connecting process by SO_PEERCRED.
func peerName(c net.Conn) string {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return "unknown"
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return "unknown"
	}
	var cred *syscall.Ucred
	_ = raw.Control(func(fd uintptr) {
		cred, err = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || cred == nil {
		return "unknown"
	}
	return fmt.Sprintf("uid=%d,pid=%d", cred.Uid, cred.Pid)
}
