package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	corev2 "github.com/sensu/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// Config represents the check plugin config.
type Config struct {
	sensu.PluginConfig
	Onion string
}

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "sensu-tor-check",
			Short:    "Sensu check for onion urls",
			Keyspace: "sensu.io/plugins/sensu-tor-check/config",
		},
	}

	options = []sensu.ConfigOption{
		&sensu.PluginConfigOption[string]{
			Path:      "onion",
			Env:       "CHECK_ONION",
			Argument:  "onion",
			Shorthand: "o",
			Usage:     "Onion address to check",
			Value:     &plugin.Onion,
		},
	}
	torProxy string = "socks5://127.0.0.1:9050" // 9150 w/ Tor Browser
)

func main() {
	useStdin := false
	fi, err := os.Stdin.Stat()
	if err != nil {
		fmt.Printf("Error check stdin: %v\n", err)
		panic(err)
	}
	//Check the Mode bitmask for Named Pipe to indicate stdin is connected
	if fi.Mode()&os.ModeNamedPipe != 0 {
		log.Println("using stdin")
		useStdin = true
	}

	check := sensu.NewGoCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, useStdin)
	check.Execute()
}

func checkArgs(event *corev2.Event) (int, error) {
	// A bad address is a configuration issue, not a service failure: report
	// unknown so it is not mistaken for the onion service being down.
	if len(plugin.Onion) == 0 {
		return sensu.CheckStateUnknown, fmt.Errorf("onion address is required")
	}
	onionUrl, err := url.Parse(plugin.Onion)
	if err != nil {
		return sensu.CheckStateUnknown, fmt.Errorf("onion address %q is not a valid URL: %s", plugin.Onion, err)
	}
	if onionUrl.Scheme != "http" && onionUrl.Scheme != "https" {
		return sensu.CheckStateUnknown, fmt.Errorf("onion address must start with http:// or https://, got %q", plugin.Onion)
	}
	if onionUrl.Host == "" {
		return sensu.CheckStateUnknown, fmt.Errorf("onion address %q has no host", plugin.Onion)
	}
	if !strings.HasSuffix(strings.ToLower(onionUrl.Hostname()), ".onion") {
		return sensu.CheckStateUnknown, fmt.Errorf("onion address host must end in .onion, got %q", onionUrl.Hostname())
	}
	return sensu.CheckStateOK, nil
}

func executeCheck(event *corev2.Event) (int, error) {
	// Thanks to https://www.devdungeon.com/content/making-tor-http-requests-go

	// Parse Tor proxy URL string to a URL type
	torProxyUrl, err := url.Parse(torProxy)
	if err != nil {
		fmt.Printf("error parsing Tor proxy URL(%s): %s\n", torProxy, err)
		return sensu.CheckStateUnknown, nil
	}

	// Set up a custom HTTP transport to use the proxy and create the client
	torTransport := &http.Transport{Proxy: http.ProxyURL(torProxyUrl)}
	client := &http.Client{Transport: torTransport, Timeout: time.Second * 30}

	// Make request
	resp, err := client.Get(plugin.Onion)
	if err != nil {
		fmt.Printf("error making GET request: %s\n", err)
		return sensu.CheckStateCritical, nil
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	fmt.Printf("%s return status code: %v\n", plugin.Onion, resp.StatusCode)
	// Expect only 200
	if resp.StatusCode != http.StatusOK {
		return sensu.CheckStateCritical, nil
	}

	// Read response
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("error reading body of response: %s\n", err)
		return sensu.CheckStateCritical, nil
	}
	return sensu.CheckStateOK, nil
}
