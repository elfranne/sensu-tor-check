package main

import (
	"testing"

	"github.com/sensu/sensu-plugin-sdk/sensu"
)

func TestCheckArgs(t *testing.T) {
	original := plugin.Onion
	defer func() { plugin.Onion = original }()

	cases := []struct {
		onion string
		want  int
	}{
		{"", sensu.CheckStateUnknown},
		{"abcdef.onion", sensu.CheckStateUnknown},
		{"http://", sensu.CheckStateUnknown},
		{"ftp://abcdef.onion", sensu.CheckStateUnknown},
		{"http://example.com", sensu.CheckStateUnknown},
		{"http://abcdef.onion", sensu.CheckStateOK},
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
