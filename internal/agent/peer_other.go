//go:build !linux

package agent

import "net"

func peerName(net.Conn) string { return "local" }
