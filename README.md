[![Sensu Bonsai Asset](https://img.shields.io/badge/Bonsai-Download%20Me-brightgreen.svg?colorB=89C967&logo=sensu)](https://bonsai.sensu.io/assets/elfranne/sensu-tor-check)
![Go Test](https://github.com/elfranne/sensu-tor-check/workflows/Go%20Test/badge.svg)
![goreleaser](https://github.com/elfranne/sensu-tor-check/workflows/goreleaser/badge.svg)

# sensu-tor-check

## Table of Contents

- [Overview](#overview)
- [Usage examples](#usage-examples)
- [Exit codes](#exit-codes)
- [Configuration](#configuration)
  - [Asset registration](#asset-registration)
  - [Check definition](#check-definition)
  - [Annotation overrides](#annotation-overrides)
- [Installation from source](#installation-from-source)
- [Additional notes](#additional-notes)
- [Contributing](#contributing)

## Overview

The sensu-tor-check is a [Sensu Check][1] that verifies an onion service is reachable
over Tor. It issues an HTTP GET to the address given by `--onion` through the SOCKS
proxy given by `--proxy`, and reports OK only when the service answers `200` and the
response body transfers completely.

A Tor daemon must already be running and reachable at `--proxy`; this plugin does not
start one. On a host running the standard `tor` package the default
`socks5://127.0.0.1:9050` is correct. If you are pointing it at Tor Browser instead,
use port `9150`.

## Usage examples

```text
Sensu check for onion urls

Usage:
  sensu-tor-check [flags]
  sensu-tor-check [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  version     Print the version number of this plugin

Flags:
  -h, --help           help for sensu-tor-check
  -o, --onion string   Onion address to check
  -p, --proxy string   Tor proxy to connect through (9150 w/ Tor Browser) (default "socks5://127.0.0.1:9050")
  -t, --timeout int    Seconds to wait for the request to complete (default 60)
```

Check an onion service through the local Tor daemon, allowing 45 seconds:

```sh
sensu-tor-check --onion http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion --timeout 45
```

Check over HTTPS through Tor Browser's proxy:

```sh
sensu-tor-check -o https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion -p socks5://127.0.0.1:9150
```

Onion services are slow to reach compared to clearnet, and a first connection to a
service the daemon has no circuit for can take considerably longer than a subsequent
one. If you see intermittent failures, raise `--timeout` before suspecting the service.

## Exit codes

CRITICAL means the onion service is at fault. UNKNOWN means this check could not reach
a verdict about it — nobody should be paged about the service on an UNKNOWN.

| Code | State | When |
| --- | --- | --- |
| `0` | OK | The service answered `200` and the body transferred completely |
| `2` | CRITICAL | Tor could not reach the service, the service answered a status other than `200`, or the body failed mid-transfer |
| `3` | UNKNOWN | The configuration is invalid, or the Tor proxy itself could not be reached |

If stdin cannot be inspected at startup the plugin panics, which exits `2` with a Go
stack trace as the check output.

## Configuration

| Flag | Environment variable | Default | Notes |
| --- | --- | --- | --- |
| `-o`, `--onion` | `CHECK_ONION` | *(required)* | Must start with `http://` or `https://`, and the host must be a name ending in `.onion` |
| `-p`, `--proxy` | `CHECK_PROXY` | `socks5://127.0.0.1:9050` | Scheme must be `socks5`, `socks5h`, `http` or `https`. Tor serves SOCKS on `SocksPort` and HTTP on `HTTPTunnelPort` |
| `-t`, `--timeout` | `CHECK_TIMEOUT` | `60` | Seconds allowed for the whole request, including connecting through Tor. Must be greater than zero |

### Asset registration

[Sensu Assets][2] are the best way to make use of this plugin. If you're not using an asset, please
consider doing so! If you're using sensuctl 5.13 with Sensu Backend 5.13 or later, you can use the
following command to add the asset:

```sh
sensuctl asset add elfranne/sensu-tor-check
```

If you're using an earlier version of sensuctl, you can find the asset on the [Bonsai Asset Index][3].

### Check definition

```yml
---
type: CheckConfig
api_version: core/v2
metadata:
  name: sensu-tor-check
  namespace: default
spec:
  command: sensu-tor-check --onion http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion
  subscriptions:
  - system
  runtime_assets:
  - elfranne/sensu-tor-check
  interval: 300
  timeout: 90
```

Keep the check's `timeout` above the plugin's `--timeout`, or the agent will kill the
plugin before it can report, and you will get an agent-generated failure instead of the
plugin's own exit code.

### Annotation overrides

Every option can also be set per entity or per check through an annotation under the
plugin's keyspace:

```yml
metadata:
  annotations:
    sensu.io/plugins/sensu-tor-check/config/onion: http://someotherservice.onion
    sensu.io/plugins/sensu-tor-check/config/timeout: "90"
```

This lets one check definition cover many entities that each watch a different address.

Overrides only apply when the agent pipes the event to the plugin, so the check must be
defined with `stdin: true`. A check annotation wins over an entity annotation, and either
wins over the flag in the check command.

## Installation from source

The preferred way of installing and deploying this plugin is to use it as an Asset. If you would
like to compile and install the plugin from source or contribute to it, download the latest version
or create an executable script from this source.

From the local path of the sensu-tor-check repository:

```sh
go build
```

## Additional notes

- **Onion addresses only.** A clearnet URL is rejected as a configuration error rather
  than checked. This is a change in behaviour — earlier versions accepted any URL, so
  anyone who was pointing this at a clearnet address to test Tor egress will now get
  UNKNOWN.

- **Redirects must stay on `.onion`.** A redirect to any other host is refused, because
  a clearnet page can happily answer `200` while the onion service it replaced is gone.
  The usual limit of 10 redirects still applies.

- **Only `200` is OK.** Any other status is CRITICAL, including redirects that exhaust
  the hop limit. If the service you are watching legitimately answers something else,
  this check is not the right tool for it.

## Contributing

For more information about contributing to this plugin, see [Contributing][4].

[1]: https://docs.sensu.io/sensu-go/latest/reference/checks/
[2]: https://docs.sensu.io/sensu-go/latest/reference/assets/
[3]: https://bonsai.sensu.io/assets/elfranne/sensu-tor-check
[4]: https://github.com/sensu/sensu-go/blob/master/CONTRIBUTING.md
