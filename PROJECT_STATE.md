# Project State - DHCP Server
Last updated: 2026-01-22 10:00

## Credentials & Access
- SSH: N/A
- DB: SQLite (local file: dhcp.db)
- GitHub: https://github.com/mstfugurlu/dhcp-server

## Tech Stack
- Language: Go 1.21
- Framework: net/http (stdlib)
- Database: SQLite3
- Test: `go test ./...`
- Build: `go build -o dhcpd.exe ./cmd/dhcpd`
- Lint: `go vet ./...`

## Branch Strategy
- main: stable releases
- feature branches for development

## Current Work
- Branch: main
- Task: Initial project setup

## Deploy
- Target: Windows Server
- Method: Single exe + config.json
- Command: `dhcpd.exe -install` (Windows service)

## Phases
- [ ] Phase 1: Core DHCP protocol (ACTIVE)
  - [ ] DHCP packet parsing
  - [ ] DISCOVER/OFFER/REQUEST/ACK
  - [ ] Lease management
- [ ] Phase 2: Storage & Config
  - [ ] SQLite schema
  - [ ] Scope management
  - [ ] MAC reservations
- [ ] Phase 3: Web UI
  - [ ] Authentication
  - [ ] Dashboard
  - [ ] Scope/Lease management
- [ ] Phase 4: Windows Service
  - [ ] Service wrapper
  - [ ] Install/uninstall commands

## Features
- Multi-scope support
- Web UI with authentication
- MAC reservation
- Lease history/logging
- REST API
- Windows service

## Example Scopes
- 10.72.102.0/24: range 10.72.102.2-240
- 10.72.103.0/24: range 10.72.103.2-240

## Notes
- Fortigate-style simplicity
- Minimal dependencies
- Single exe deployment
