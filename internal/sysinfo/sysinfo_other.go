//go:build !linux

package sysinfo

// enrich is a no-op off Linux: the appliance only runs on Linux, and the
// development build on other systems reports counters as unavailable rather
// than inventing them.
func (r Reader) enrich(it *Interface) {}

func (r Reader) overlay([]Interface) {}
