package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
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
	if len(plugin.Onion) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("onion address is required")
	}
	return sensu.CheckStateOK, nil
}

func executeCheck(event *corev2.Event) (int, error) {
	// Thanks to https://www.devdungeon.com/content/making-tor-http-requests-go

	// Parse Tor proxy URL string to a URL type
	torProxyUrl, err := url.Parse(torProxy)
	if err != nil {
		fmt.Printf("error parsing Tor proxy URL(%s): %s", torProxy, err)
		return sensu.CheckStateCritical, nil
	}

	// Set up a custom HTTP transport to use the proxy and create the client
	torTransport := &http.Transport{Proxy: http.ProxyURL(torProxyUrl)}
	client := &http.Client{Transport: torTransport, Timeout: time.Second * 30}

	// Make request
	resp, err := client.Get(plugin.Onion)
	if err != nil {
		fmt.Printf("error making GET request: %s", err)
		return sensu.CheckStateCritical, nil
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	// Expect only 200
	if resp.StatusCode != 200 {
		fmt.Printf("%s return status code: %v", plugin.Onion, resp.StatusCode)
		return sensu.CheckStateCritical, nil
	}

	// Read response
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("error reading body of response: %s", err)
		return sensu.CheckStateCritical, nil
	}
	fmt.Printf("%s return status code: %v", plugin.Onion, resp.StatusCode)
	return sensu.CheckStateOK, nil
}
