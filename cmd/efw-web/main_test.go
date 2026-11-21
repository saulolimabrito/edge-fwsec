package main

import "testing"

func TestCheckLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:8080": true, "[::1]:8080": true, "localhost:1": true,
		"0.0.0.0:8080": false, ":8080": false, "[::]:80": false, "192.0.2.1:443": false, "bad": false,
	} {
		if got := checkLoopback(addr) == nil; got != ok {
			t.Errorf("%s: got %v want %v", addr, got, ok)
		}
	}
}
