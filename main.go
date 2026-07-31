package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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
	Onion   string
	Proxy   string
	Timeout int
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
		&sensu.PluginConfigOption[string]{
			Path:      "proxy",
			Env:       "CHECK_PROXY",
			Argument:  "proxy",
			Shorthand: "p",
			Default:   "socks5://127.0.0.1:9050",
			Usage:     "Tor proxy to connect through (9150 w/ Tor Browser)",
			Value:     &plugin.Proxy,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "timeout",
			Env:       "CHECK_TIMEOUT",
			Argument:  "timeout",
			Shorthand: "t",
			Default:   60,
			Usage:     "Seconds to wait for the request to complete",
			Value:     &plugin.Timeout,
		},
	}
	// Parsed and validated by checkArgs, which the SDK runs before
	// executeCheck.
	torProxyUrl *url.URL
)

func main() {
	useStdin := false
	fi, err := os.Stdin.Stat()
	if err != nil {
		// Without stdin the event cannot be read, so annotation overrides
		// would be silently skipped: report unknown rather than check a
		// possibly stale address.
		fmt.Printf("error checking stdin: %v\n", err)
		os.Exit(sensu.CheckStateUnknown)
	}
	//Check the Mode bitmask for Named Pipe to indicate stdin is connected
	if fi.Mode()&os.ModeNamedPipe != 0 {
		log.Println("using stdin")
		useStdin = true
	}

	check := sensu.NewGoCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, useStdin)
	check.Execute()
}

// isOnionHost reports whether host names an onion service. A bare ".onion"
// (or one preceded by an empty label) carries the suffix but names nothing,
// so something has to sit in front of it.
func isOnionHost(host string) bool {
	service, ok := strings.CutSuffix(strings.ToLower(host), ".onion")
	return ok && service != "" && !strings.HasSuffix(service, ".")
}

// checkRedirect keeps the check pointed at onion services. Following a
// redirect off .onion would leave the check reporting on whatever it landed
// on -- a clearnet page can answer 200 while the onion service it replaced is
// gone. Setting this also replaces net/http's default hop limit, so the limit
// is reimposed here.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if !isOnionHost(req.URL.Hostname()) {
		return fmt.Errorf("refusing redirect to non-onion host %q", req.URL.Hostname())
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
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
	if !isOnionHost(onionUrl.Hostname()) {
		return sensu.CheckStateUnknown, fmt.Errorf("onion address host must be a name ending in .onion, got %q", onionUrl.Hostname())
	}
	// http.Client treats a non-positive timeout as no timeout at all, which
	// would leave the check hanging until the agent kills it.
	if plugin.Timeout <= 0 {
		return sensu.CheckStateUnknown, fmt.Errorf("timeout must be greater than zero, got %d", plugin.Timeout)
	}
	proxyUrl, err := url.Parse(plugin.Proxy)
	if err != nil {
		return sensu.CheckStateUnknown, fmt.Errorf("proxy %q is not a valid URL: %s", plugin.Proxy, err)
	}
	// http.Transport understands these four; tor serves socks5 on SocksPort
	// and http on HTTPTunnelPort.
	switch proxyUrl.Scheme {
	case "socks5", "socks5h", "http", "https":
	default:
		return sensu.CheckStateUnknown, fmt.Errorf("proxy scheme must be socks5, socks5h, http or https, got %q", plugin.Proxy)
	}
	if proxyUrl.Host == "" {
		return sensu.CheckStateUnknown, fmt.Errorf("proxy %q has no host", plugin.Proxy)
	}
	torProxyUrl = proxyUrl
	return sensu.CheckStateOK, nil
}

func executeCheck(event *corev2.Event) (int, error) {
	// Thanks to https://www.devdungeon.com/content/making-tor-http-requests-go

	// http.ProxyURL(nil) would quietly connect direct, checking the address
	// outside Tor, so refuse to run rather than trust that checkArgs ran.
	if torProxyUrl == nil {
		fmt.Print("no Tor proxy configured\n")
		return sensu.CheckStateUnknown, nil
	}

	// Set up a custom HTTP transport to use the proxy and create the client
	torTransport := &http.Transport{Proxy: http.ProxyURL(torProxyUrl)}
	client := &http.Client{
		Transport:     torTransport,
		Timeout:       time.Duration(plugin.Timeout) * time.Second,
		CheckRedirect: checkRedirect,
	}

	// Make request
	resp, err := client.Get(plugin.Onion)
	if err != nil {
		// Failing to reach the proxy itself says nothing about the onion
		// service: the local tor daemon is down, so report unknown rather
		// than page someone about a service that was never contacted.
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "proxyconnect" {
			fmt.Printf("error connecting to Tor proxy %s: %s\n", plugin.Proxy, err)
			return sensu.CheckStateUnknown, nil
		}
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

	// Drain the response to confirm the body transfers, without buffering a
	// remote-controlled amount of data just to discard it.
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		fmt.Printf("error reading body of response: %s\n", err)
		return sensu.CheckStateCritical, nil
	}
	return sensu.CheckStateOK, nil
}
