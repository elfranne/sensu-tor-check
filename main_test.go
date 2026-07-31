package main

import (
	"fmt"
	"testing"

	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// restoreConfig returns the plugin config to its zero-ish state once a test
// that mutates the package-level globals is done with them.
func restoreConfig(t *testing.T) {
	onion, proxy, timeout, proxyUrl := plugin.Onion, plugin.Proxy, plugin.Timeout, torProxyUrl
	t.Cleanup(func() {
		plugin.Onion, plugin.Proxy, plugin.Timeout, torProxyUrl = onion, proxy, timeout, proxyUrl
	})
}

func TestCheckArgs(t *testing.T) {
	restoreConfig(t)
	plugin.Timeout = 60
	plugin.Proxy = "socks5://127.0.0.1:9050"

	cases := []struct {
		onion string
		want  int
	}{
		{"", sensu.CheckStateUnknown},
		{"abcdef.onion", sensu.CheckStateUnknown},
		{"http://", sensu.CheckStateUnknown},
		{"ftp://abcdef.onion", sensu.CheckStateUnknown},
		{"http://example.com", sensu.CheckStateUnknown},
		{"http://.onion", sensu.CheckStateUnknown},
		{"http://..onion", sensu.CheckStateUnknown},
		{"http://onion", sensu.CheckStateUnknown},
		{"http://abcdef.onion", sensu.CheckStateOK},
		{"http://www.abcdef.onion", sensu.CheckStateOK},
		{"https://abcdef.onion", sensu.CheckStateOK},
		{"http://ABCDEF.onion", sensu.CheckStateOK},
		{"http://abcdef.onion:8080/path", sensu.CheckStateOK},
	}

	for _, c := range cases {
		t.Run(c.onion, func(t *testing.T) {
			plugin.Onion = c.onion
			status, err := checkArgs(nil)
			if status != c.want {
				t.Errorf("checkArgs(%q) = %v (err: %v), want %v", c.onion, status, err, c.want)
			}
			if c.want == sensu.CheckStateOK && err != nil {
				t.Errorf("checkArgs(%q) returned unexpected error: %v", c.onion, err)
			}
			if c.want != sensu.CheckStateOK && err == nil {
				t.Errorf("checkArgs(%q) returned no error, want one", c.onion)
			}
		})
	}
}

func TestCheckArgsTimeout(t *testing.T) {
	restoreConfig(t)
	plugin.Onion = "http://abcdef.onion"
	plugin.Proxy = "socks5://127.0.0.1:9050"

	cases := []struct {
		timeout int
		want    int
	}{
		{0, sensu.CheckStateUnknown},
		{-1, sensu.CheckStateUnknown},
		{1, sensu.CheckStateOK},
		{60, sensu.CheckStateOK},
	}

	for _, c := range cases {
		t.Run(fmt.Sprint(c.timeout), func(t *testing.T) {
			plugin.Timeout = c.timeout
			status, err := checkArgs(nil)
			if status != c.want {
				t.Errorf("checkArgs(timeout %d) = %v (err: %v), want %v", c.timeout, status, err, c.want)
			}
			if c.want == sensu.CheckStateOK && err != nil {
				t.Errorf("checkArgs(timeout %d) returned unexpected error: %v", c.timeout, err)
			}
			if c.want != sensu.CheckStateOK && err == nil {
				t.Errorf("checkArgs(timeout %d) returned no error, want one", c.timeout)
			}
		})
	}
}

func TestCheckArgsProxy(t *testing.T) {
	restoreConfig(t)
	plugin.Onion = "http://abcdef.onion"
	plugin.Timeout = 60

	cases := []struct {
		proxy string
		want  int
	}{
		{"", sensu.CheckStateUnknown},
		{"127.0.0.1:9050", sensu.CheckStateUnknown},
		{"socks5://", sensu.CheckStateUnknown},
		{"ftp://127.0.0.1:9050", sensu.CheckStateUnknown},
		{"socks5://127.0.0.1:9050", sensu.CheckStateOK},
		{"socks5://127.0.0.1:9150", sensu.CheckStateOK},
		{"socks5h://tor:9050", sensu.CheckStateOK},
		{"http://127.0.0.1:9080", sensu.CheckStateOK},
	}

	for _, c := range cases {
		t.Run(c.proxy, func(t *testing.T) {
			torProxyUrl = nil
			plugin.Proxy = c.proxy
			status, err := checkArgs(nil)
			if status != c.want {
				t.Errorf("checkArgs(proxy %q) = %v (err: %v), want %v", c.proxy, status, err, c.want)
			}
			if c.want != sensu.CheckStateOK {
				if err == nil {
					t.Errorf("checkArgs(proxy %q) returned no error, want one", c.proxy)
				}
				// A rejected proxy must not reach executeCheck, which would
				// otherwise connect direct.
				if torProxyUrl != nil {
					t.Errorf("checkArgs(proxy %q) set torProxyUrl to %v, want nil", c.proxy, torProxyUrl)
				}
				return
			}
			if err != nil {
				t.Errorf("checkArgs(proxy %q) returned unexpected error: %v", c.proxy, err)
			}
			if torProxyUrl == nil || torProxyUrl.String() != c.proxy {
				t.Errorf("checkArgs(proxy %q) set torProxyUrl to %v, want %q", c.proxy, torProxyUrl, c.proxy)
			}
		})
	}
}
