package dhcp

import (
	"encoding/binary"
	"net"
)

// DHCP message types
const (
	Discover = 1
	Offer    = 2
	Request  = 3
	Decline  = 4
	Ack      = 5
	Nak      = 6
	Release  = 7
	Inform   = 8
)

// DHCP options
const (
	OptSubnetMask        = 1
	OptRouter            = 3
	OptDNS               = 6
	OptHostname          = 12
	OptDomainName        = 15
	OptBroadcast         = 28
	OptRequestedIP       = 50
	OptLeaseTime         = 51
	OptMessageType       = 53
	OptServerID          = 54
	OptParamRequestList  = 55
	OptRenewalTime       = 58
	OptRebindingTime     = 59
	OptClientID          = 61
	OptEnd               = 255
)

type Packet struct {
	Op       byte
	HType    byte
	HLen     byte
	Hops     byte
	XID      uint32
	Secs     uint16
	Flags    uint16
	CIAddr   net.IP
	YIAddr   net.IP
	SIAddr   net.IP
	GIAddr   net.IP
	CHAddr   net.HardwareAddr
	SName    [64]byte
	File     [128]byte
	Options  map[byte][]byte
}

func ParsePacket(data []byte) (*Packet, error) {
	if len(data) < 240 {
		return nil, ErrPacketTooShort
	}

	p := &Packet{
		Op:      data[0],
		HType:   data[1],
		HLen:    data[2],
		Hops:    data[3],
		XID:     binary.BigEndian.Uint32(data[4:8]),
		Secs:    binary.BigEndian.Uint16(data[8:10]),
		Flags:   binary.BigEndian.Uint16(data[10:12]),
		CIAddr:  net.IP(data[12:16]),
		YIAddr:  net.IP(data[16:20]),
		SIAddr:  net.IP(data[20:24]),
		GIAddr:  net.IP(data[24:28]),
		CHAddr:  net.HardwareAddr(data[28:34]),
		Options: make(map[byte][]byte),
	}

	copy(p.SName[:], data[44:108])
	copy(p.File[:], data[108:236])

	// parse options after magic cookie (99, 130, 83, 99)
	if len(data) > 240 {
		p.parseOptions(data[240:])
	}

	return p, nil
}

func (p *Packet) parseOptions(data []byte) {
	i := 0
	for i < len(data) {
		opt := data[i]
		if opt == OptEnd || opt == 0 {
			break
		}
		i++
		if i >= len(data) {
			break
		}
		length := int(data[i])
		i++
		if i+length > len(data) {
			break
		}
		p.Options[opt] = data[i : i+length]
		i += length
	}
}

func (p *Packet) MessageType() byte {
	if mt, ok := p.Options[OptMessageType]; ok && len(mt) > 0 {
		return mt[0]
	}
	return 0
}

func (p *Packet) RequestedIP() net.IP {
	if ip, ok := p.Options[OptRequestedIP]; ok && len(ip) == 4 {
		return net.IP(ip)
	}
	return nil
}

func (p *Packet) MAC() string {
	return p.CHAddr.String()
}

func (p *Packet) Marshal() []byte {
	buf := make([]byte, 240)

	buf[0] = p.Op
	buf[1] = p.HType
	buf[2] = p.HLen
	buf[3] = p.Hops
	binary.BigEndian.PutUint32(buf[4:8], p.XID)
	binary.BigEndian.PutUint16(buf[8:10], p.Secs)
	binary.BigEndian.PutUint16(buf[10:12], p.Flags)
	copy(buf[12:16], p.CIAddr.To4())
	copy(buf[16:20], p.YIAddr.To4())
	copy(buf[20:24], p.SIAddr.To4())
	copy(buf[24:28], p.GIAddr.To4())
	copy(buf[28:34], p.CHAddr)
	copy(buf[44:108], p.SName[:])
	copy(buf[108:236], p.File[:])

	// magic cookie
	buf[236] = 99
	buf[237] = 130
	buf[238] = 83
	buf[239] = 99

	// options
	opts := p.marshalOptions()
	buf = append(buf, opts...)
	buf = append(buf, OptEnd)

	return buf
}

func (p *Packet) marshalOptions() []byte {
	var buf []byte
	for opt, val := range p.Options {
		buf = append(buf, opt, byte(len(val)))
		buf = append(buf, val...)
	}
	return buf
}

type ReplyBuilder struct {
	request *Packet
	options map[byte][]byte
}

func NewReply(request *Packet) *ReplyBuilder {
	return &ReplyBuilder{
		request: request,
		options: make(map[byte][]byte),
	}
}

func (b *ReplyBuilder) MessageType(t byte) *ReplyBuilder {
	b.options[OptMessageType] = []byte{t}
	return b
}

func (b *ReplyBuilder) ServerID(ip net.IP) *ReplyBuilder {
	b.options[OptServerID] = ip.To4()
	return b
}

func (b *ReplyBuilder) SubnetMask(mask net.IPMask) *ReplyBuilder {
	b.options[OptSubnetMask] = []byte(mask)
	return b
}

func (b *ReplyBuilder) Router(ip net.IP) *ReplyBuilder {
	b.options[OptRouter] = ip.To4()
	return b
}

func (b *ReplyBuilder) DNS(servers []net.IP) *ReplyBuilder {
	var buf []byte
	for _, s := range servers {
		buf = append(buf, s.To4()...)
	}
	b.options[OptDNS] = buf
	return b
}

func (b *ReplyBuilder) LeaseTime(seconds uint32) *ReplyBuilder {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, seconds)
	b.options[OptLeaseTime] = buf
	return b
}

func (b *ReplyBuilder) Build(yiaddr net.IP, siaddr net.IP) *Packet {
	return &Packet{
		Op:      2, // reply
		HType:   b.request.HType,
		HLen:    b.request.HLen,
		Hops:    0,
		XID:     b.request.XID,
		Secs:    0,
		Flags:   b.request.Flags,
		CIAddr:  net.IPv4zero,
		YIAddr:  yiaddr,
		SIAddr:  siaddr,
		GIAddr:  b.request.GIAddr,
		CHAddr:  b.request.CHAddr,
		Options: b.options,
	}
}
