package dhcp

import "errors"

var (
	ErrPacketTooShort = errors.New("dhcp: packet too short")
	ErrNoAvailableIP  = errors.New("dhcp: no available IP in pool")
	ErrScopeNotFound  = errors.New("dhcp: scope not found for network")
)
