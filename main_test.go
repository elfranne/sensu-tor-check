package main

import (
	"fmt"
	"testing"

	"github.com/sensu/sensu-plugin-sdk/sensu"
)

func TestCheckArgs(t *testing.T) {
	originalOnion, originalTimeout := plugin.Onion, plugin.Timeout
	defer func() { plugin.Onion, plugin.Timeout = originalOnion, originalTimeout }()
	plugin.Timeout = 60

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
	originalOnion, originalTimeout := plugin.Onion, plugin.Timeout
	defer func() { plugin.Onion, plugin.Timeout = originalOnion, originalTimeout }()
	plugin.Onion = "http://abcdef.onion"

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
