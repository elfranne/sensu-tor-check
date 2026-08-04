# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic
Versioning](http://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.3.0] - 2026-08-04

### Added

- `-p`/`--proxy` (`CHECK_PROXY`) sets the Tor proxy to connect through. It was
  previously hard-coded to `socks5://127.0.0.1:9050`, which is still the
  default. `socks5`, `socks5h`, `http` and `https` are accepted, so the check
  can now run against Tor Browser's port 9150, a `HTTPTunnelPort`, or a Tor
  daemon on another host.
- `-t`/`--timeout` (`CHECK_TIMEOUT`) sets the number of seconds allowed for the
  whole request.
- The onion address is now validated before any request is made: it must parse
  as a URL, use `http` or `https`, and have a host.
- README documenting the flags, the exit codes, annotation overrides and the
  redirect policy. It previously described the check-plugin-template it was
  generated from.

### Changed

- **Configuration errors now exit `3` (unknown) rather than `1` (warning).** A
  missing or malformed onion address says nothing about the service being
  watched, so it should not reach whoever is on call for that service.
- **An unreachable Tor proxy now exits `3` (unknown) rather than `2`
  (critical).** If the local Tor daemon is down the onion service was never
  contacted, so reporting it as down is a false statement.
- The request timeout default is now 60 seconds, up from 30. Reaching an onion
  service the daemon has no circuit for regularly took longer than 30 seconds.
- The response status code is printed on success as well as on failure.
- Check output lines are terminated with newlines. They previously ran together
  in the event output.
- The response body is drained rather than buffered, so a large or endless
  response no longer allocates a remote-controlled amount of memory just to
  discard it.

### Removed

- **The onion address must now be an `http`/`https` URL whose host ends in
  `.onion`.** Anything else is rejected as a configuration error and exits `3`.
  This is breaking for anyone who pointed the check at a clearnet URL to test
  Tor egress; there is no flag to restore the old behaviour.
- **Redirects that leave `.onion` are refused** and exit `2`. A clearnet page
  can answer `200` while the onion service it replaced is gone, so following
  one meant reporting OK for a service that no longer existed. The usual limit
  of 10 redirects still applies.

## [0.2.2] - 2025-01-10

### Changed

- Go 1.23.4 and dependency updates. No change to check behaviour.

## [0.2.1] - 2024-11-21

### Changed

- Dependency updates. No change to check behaviour.

## [0.2] - 2024-09-16

### Changed

- Go 1.23.1 and dependency updates. No change to check behaviour.

## [0.1.1] - 2024-07-03

### Changed

- Go 1.22, dependency updates and GitHub Actions workflow updates. No change to
  check behaviour.

## [0.1.0] - 2024-03-27

### Added

- Initial release. Fetches an onion address over a hard-coded local Tor SOCKS
  proxy with a 30 second timeout, and reports OK only on a `200` response.

[0.3.0]: https://github.com/elfranne/sensu-tor-check/compare/0.2.2...0.3.0
[0.2.2]: https://github.com/elfranne/sensu-tor-check/compare/0.2.1...0.2.2
[0.2.1]: https://github.com/elfranne/sensu-tor-check/compare/0.2...0.2.1
[0.2]: https://github.com/elfranne/sensu-tor-check/compare/0.1.1...0.2
[0.1.1]: https://github.com/elfranne/sensu-tor-check/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/elfranne/sensu-tor-check/releases/tag/0.1.0
