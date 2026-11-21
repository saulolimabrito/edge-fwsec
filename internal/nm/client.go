package nm

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	busName      = "org.freedesktop.NetworkManager"
	nmPath       = dbus.ObjectPath("/org/freedesktop/NetworkManager")
	settingsPath = dbus.ObjectPath("/org/freedesktop/NetworkManager/Settings")
	ifNM         = "org.freedesktop.NetworkManager"
	ifSettings   = "org.freedesktop.NetworkManager.Settings"
	ifConn       = "org.freedesktop.NetworkManager.Settings.Connection"

	// NMCheckpointCreateFlags (nm-dbus-types): on rollback delete profiles
	// created after the checkpoint; NM then removes the software devices
	// (VLANs) it created for them. DISCONNECT_NEW_DEVICES (0x04) is not
	// used: NM 1.58 rejects it unless the device list is empty, and an
	// empty list would snapshot every device on the host (verified).
	flagDeleteNewConnections = 0x02
	// NMSettingsAddConnection2Flags / NMSettingsUpdate2Flags: persist.
	flagToDisk = 0x1

	// SafetyMargin is added to the agent deadline for NetworkManager's own
	// rollback timer, a second line of defence if the agent dies.
	SafetyMargin = 30 * time.Second
)

// Client talks to NetworkManager on the system bus.
type Client struct {
	conn *dbus.Conn
}

// Connect opens a private system bus connection.
func Connect() (*Client, error) {
	c, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	return &Client{conn: c}, nil
}

// Close releases the bus connection.
func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) obj(p dbus.ObjectPath) dbus.BusObject { return c.conn.Object(busName, p) }

// Version returns NetworkManager's version string.
func (c *Client) Version() (string, error) {
	v, err := c.obj(nmPath).GetProperty(ifNM + ".Version")
	if err != nil {
		return "", err
	}
	s, _ := v.Value().(string)
	return s, nil
}

// Device returns the D-Bus path of a kernel interface, ok=false if absent.
func (c *Client) Device(iface string) (dbus.ObjectPath, bool) {
	var p dbus.ObjectPath
	if err := c.obj(nmPath).Call(ifNM+".GetDeviceByIpIface", 0, iface).Store(&p); err != nil {
		return "", false
	}
	return p, true
}

// Checkpoints lists active checkpoints.
func (c *Client) Checkpoints() ([]dbus.ObjectPath, error) {
	v, err := c.obj(nmPath).GetProperty(ifNM + ".Checkpoints")
	if err != nil {
		return nil, err
	}
	ps, _ := v.Value().([]dbus.ObjectPath)
	return ps, nil
}

// CheckpointCreate snapshots devices; NetworkManager rolls back by itself
// after timeout unless destroyed.
func (c *Client) CheckpointCreate(devices []dbus.ObjectPath, timeout time.Duration) (dbus.ObjectPath, error) {
	var cp dbus.ObjectPath
	err := c.obj(nmPath).Call(ifNM+".CheckpointCreate", 0, devices, uint32(timeout/time.Second),
		uint32(flagDeleteNewConnections)).Store(&cp)
	return cp, err
}

// CheckpointRollback restores the snapshot; results maps device paths to
// NMRollbackResult (0 = ok).
func (c *Client) CheckpointRollback(cp dbus.ObjectPath) (map[string]uint32, error) {
	var res map[string]uint32
	err := c.obj(nmPath).Call(ifNM+".CheckpointRollback", 0, cp).Store(&res)
	return res, err
}

// CheckpointDestroy keeps the current state and drops the snapshot.
func (c *Client) CheckpointDestroy(cp dbus.ObjectPath) error {
	return c.obj(nmPath).Call(ifNM+".CheckpointDestroy", 0, cp).Err
}

// connByUUID returns the settings path of a profile, ok=false if absent.
func (c *Client) connByUUID(uuid string) (dbus.ObjectPath, bool) {
	var p dbus.ObjectPath
	if err := c.obj(settingsPath).Call(ifSettings+".GetConnectionByUuid", 0, uuid).Store(&p); err != nil {
		return "", false
	}
	return p, true
}

// Upsert creates or replaces a profile, persisted to disk.
func (c *Client) Upsert(p Profile) (dbus.ObjectPath, error) {
	if path, ok := c.connByUUID(p.UUID); ok {
		var res map[string]dbus.Variant
		err := c.obj(path).Call(ifConn+".Update2", 0, p.Settings, uint32(flagToDisk), map[string]dbus.Variant{}).Store(&res)
		return path, err
	}
	var path dbus.ObjectPath
	var res map[string]dbus.Variant
	err := c.obj(settingsPath).Call(ifSettings+".AddConnection2", 0, p.Settings, uint32(flagToDisk), map[string]dbus.Variant{}).Store(&path, &res)
	return path, err
}

// OwnedProfiles lists Edge FWSec profiles (id prefix + derived UUID).
func (c *Client) OwnedProfiles() (map[string]dbus.ObjectPath, error) {
	m, _, err := c.ownedProfiles()
	return m, err
}

// ownedDevices returns the interface names bound to Edge FWSec profiles.
func (c *Client) ownedDevices() ([]string, error) {
	_, devs, err := c.ownedProfiles()
	return devs, err
}

func (c *Client) ownedProfiles() (map[string]dbus.ObjectPath, []string, error) {
	var paths []dbus.ObjectPath
	if err := c.obj(settingsPath).Call(ifSettings+".ListConnections", 0).Store(&paths); err != nil {
		return nil, nil, err
	}
	out := map[string]dbus.ObjectPath{}
	var devs []string
	for _, p := range paths {
		var s map[string]map[string]dbus.Variant
		if err := c.obj(p).Call(ifConn+".GetSettings", 0).Store(&s); err != nil {
			continue // profile vanished meanwhile
		}
		id, _ := s["connection"]["id"].Value().(string)
		uuid, _ := s["connection"]["uuid"].Value().(string)
		if Owned(id, uuid) {
			out[uuid] = p
			if d, _ := s["connection"]["interface-name"].Value().(string); d != "" {
				devs = append(devs, d)
			}
		}
	}
	return out, devs, nil
}

// Activate brings a profile up. device "/" lets NM pick (virtual devices).
func (c *Client) Activate(conn, device dbus.ObjectPath) error {
	var active dbus.ObjectPath
	return c.obj(nmPath).Call(ifNM+".ActivateConnection", 0, conn, device, dbus.ObjectPath("/")).Store(&active)
}

// Network applies profiles under a checkpoint. It implements the agent's
// network step.
type Network struct {
	Client *Client
}

// Begin snapshots every device the profiles touch, then writes and
// activates the profiles and removes stale Edge FWSec profiles. On error
// the checkpoint is rolled back before returning.
func (n *Network) Begin(ctx context.Context, profiles []Profile, deadline time.Duration) (string, error) {
	// Snapshot the devices of the new profiles and of every existing Edge
	// FWSec profile: a profile the change deletes (e.g. a removed VLAN)
	// must come back on rollback.
	names := []string{}
	for _, p := range profiles {
		names = append(names, p.Device, p.Parent)
	}
	existing, err := n.Client.ownedDevices()
	if err != nil {
		return "", err
	}
	names = append(names, existing...)
	var devs []dbus.ObjectPath
	seen := map[string]bool{}
	for _, d := range names {
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		if path, ok := n.Client.Device(d); ok {
			devs = append(devs, path)
		}
	}
	if len(devs) == 0 {
		// An empty list would snapshot every device on the host; refuse.
		return "", errors.New("none of the configured devices exist; refusing an all-devices checkpoint")
	}
	cp, err := n.Client.CheckpointCreate(devs, deadline+SafetyMargin)
	if err != nil {
		return "", fmt.Errorf("checkpoint: %w", err)
	}
	if err := n.write(profiles); err != nil {
		if _, rerr := n.Client.CheckpointRollback(cp); rerr != nil {
			err = errors.Join(err, fmt.Errorf("rollback: %w", rerr))
		}
		return "", err
	}
	return string(cp), nil
}

func (n *Network) write(profiles []Profile) error {
	keep := map[string]bool{}
	// Physical/parent profiles first so VLAN parents are up before children.
	ordered := slices.Clone(profiles)
	slices.SortStableFunc(ordered, func(a, b Profile) int {
		return boolInt(a.Parent != "") - boolInt(b.Parent != "")
	})
	for _, p := range ordered {
		keep[p.UUID] = true
		path, err := n.Client.Upsert(p)
		if err != nil {
			return fmt.Errorf("profile %s: %w", p.ID, err)
		}
		dev := dbus.ObjectPath("/")
		if d, ok := n.Client.Device(p.Device); ok && p.Parent == "" {
			dev = d
		}
		if err := n.Client.Activate(path, dev); err != nil {
			return fmt.Errorf("activate %s: %w", p.ID, err)
		}
	}
	owned, err := n.Client.OwnedProfiles()
	if err != nil {
		return err
	}
	for uuid, path := range owned {
		if !keep[uuid] {
			if err := n.Client.obj(path).Call(ifConn+".Delete", 0).Err; err != nil {
				return fmt.Errorf("delete stale profile %s: %w", uuid, err)
			}
		}
	}
	return nil
}

// Commit keeps the new network state.
func (n *Network) Commit(_ context.Context, checkpoint string) error {
	return n.Client.CheckpointDestroy(dbus.ObjectPath(checkpoint))
}

// Rollback restores the checkpoint. A missing checkpoint (NetworkManager
// restarted or its own timer fired) is reported so the caller can rewrite
// the confirmed profiles instead.
func (n *Network) Rollback(_ context.Context, checkpoint string) error {
	cps, err := n.Client.Checkpoints()
	if err != nil {
		return err
	}
	if !slices.Contains(cps, dbus.ObjectPath(checkpoint)) {
		return ErrCheckpointGone
	}
	res, err := n.Client.CheckpointRollback(dbus.ObjectPath(checkpoint))
	if err != nil {
		return err
	}
	for dev, r := range res {
		if r != 0 {
			return fmt.Errorf("rollback of %s returned NMRollbackResult %d", dev, r)
		}
	}
	return nil
}

// Restore rewrites and activates the confirmed profiles without a
// checkpoint (used when the checkpoint is gone).
func (n *Network) Restore(_ context.Context, profiles []Profile) error {
	return n.write(profiles)
}

// ErrCheckpointGone means NetworkManager no longer has the checkpoint.
var ErrCheckpointGone = errors.New("checkpoint no longer exists")

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
