package main

import (
	"net/http"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		cfHeader   string
		want       string
	}{
		{"direct, no CF header", "203.0.113.7:54321", "", "203.0.113.7"},
		{"direct, spoofed CF header ignored", "203.0.113.7:54321", "1.2.3.4", "203.0.113.7"},
		{"behind Cloudflare, header trusted", "172.68.0.1:443", "198.51.100.9", "198.51.100.9"},
		{"behind Cloudflare, no header falls back", "172.68.0.1:443", "", "172.68.0.1"},
		{"behind Cloudflare, garbage header falls back", "172.68.0.1:443", "not-an-ip", "172.68.0.1"},
		{"no port in RemoteAddr", "203.0.113.7", "", "203.0.113.7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: c.remoteAddr, Header: http.Header{}}
			if c.cfHeader != "" {
				r.Header.Set("CF-Connecting-IP", c.cfHeader)
			}
			if got := clientIP(r); got != c.want {
				t.Errorf("clientIP(%q, CF-Connecting-IP=%q) = %q, want %q", c.remoteAddr, c.cfHeader, got, c.want)
			}
		})
	}
}
