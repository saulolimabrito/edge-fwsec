package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Call sends one request to the agent socket and returns its response.
func Call(ctx context.Context, socket string, req *Request) (*Response, error) {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return nil, err
	}
	if uc, ok := c.(*net.UnixConn); ok {
		_ = uc.CloseWrite() // signals end of request
	}
	var resp Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return &resp, nil
}
