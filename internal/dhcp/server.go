package dhcp

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
	"time"

	"github.com/mstfugurlu/dhcp-server/internal/store"
)

type Server struct {
	store    *store.Store
	serverIP net.IP
	conn     *net.UDPConn
	mu       sync.RWMutex
	running  bool
}

func NewServer(st *store.Store, serverIP net.IP) *Server {
	return &Server{
		store:    st,
		serverIP: serverIP,
	}
}

func (s *Server) Start() error {
	addr := &net.UDPAddr{Port: 67}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	s.conn = conn
	s.running = true

	log.Printf("DHCP server listening on :67")

	go s.cleanupLoop()

	buf := make([]byte, 1500)
	for s.running {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if s.running {
				log.Printf("read error: %v", err)
			}
			continue
		}

		go s.handlePacket(buf[:n], addr)
	}

	return nil
}

func (s *Server) Stop() {
	s.running = false
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s *Server) handlePacket(data []byte, addr *net.UDPAddr) {
	pkt, err := ParsePacket(data)
	if err != nil {
		log.Printf("parse error: %v", err)
		return
	}

	msgType := pkt.MessageType()
	mac := pkt.MAC()

	log.Printf("DHCP %s from %s", msgTypeName(msgType), mac)

	switch msgType {
	case Discover:
		s.handleDiscover(pkt)
	case Request:
		s.handleRequest(pkt)
	case Release:
		s.handleRelease(pkt)
	case Decline:
		s.handleDecline(pkt)
	}
}

func (s *Server) handleDiscover(pkt *Packet) {
	mac := pkt.MAC()

	// check reservation first
	reservation, _ := s.store.FindReservationByMAC(mac)
	if reservation != nil {
		s.sendOffer(pkt, net.ParseIP(reservation.IP), reservation.ScopeID)
		return
	}

	// check existing lease
	lease, _ := s.store.FindLeaseByMAC(mac)
	if lease != nil {
		s.sendOffer(pkt, net.ParseIP(lease.IP), lease.ScopeID)
		return
	}

	// find scope and allocate new IP
	scope, ip := s.allocateIP(pkt)
	if scope == nil || ip == nil {
		log.Printf("no available IP for %s", mac)
		return
	}

	s.sendOffer(pkt, ip, scope.ID)
}

func (s *Server) handleRequest(pkt *Packet) {
	mac := pkt.MAC()
	requestedIP := pkt.RequestedIP()
	if requestedIP == nil && !pkt.CIAddr.IsUnspecified() {
		requestedIP = pkt.CIAddr
	}

	if requestedIP == nil {
		log.Printf("no requested IP in REQUEST from %s", mac)
		s.sendNak(pkt)
		return
	}

	// verify the IP is valid for this client
	reservation, _ := s.store.FindReservationByMAC(mac)
	if reservation != nil {
		if reservation.IP != requestedIP.String() {
			log.Printf("MAC %s has reservation for %s but requested %s", mac, reservation.IP, requestedIP)
			s.sendNak(pkt)
			return
		}
		s.sendAck(pkt, requestedIP, reservation.ScopeID)
		return
	}

	// check existing lease
	lease, _ := s.store.FindLeaseByMAC(mac)
	if lease != nil && lease.IP == requestedIP.String() {
		s.sendAck(pkt, requestedIP, lease.ScopeID)
		return
	}

	// new allocation
	existingLease, _ := s.store.FindLeaseByIP(requestedIP.String())
	if existingLease != nil && existingLease.MAC != mac {
		log.Printf("IP %s already leased to %s, denying %s", requestedIP, existingLease.MAC, mac)
		s.sendNak(pkt)
		return
	}

	// find scope for this IP
	scope, _ := s.store.FindScopeForNetwork(requestedIP)
	if scope == nil {
		log.Printf("no scope for IP %s", requestedIP)
		s.sendNak(pkt)
		return
	}

	s.sendAck(pkt, requestedIP, scope.ID)
}

func (s *Server) handleRelease(pkt *Packet) {
	mac := pkt.MAC()
	lease, _ := s.store.FindLeaseByMAC(mac)
	if lease != nil {
		s.store.DeleteLease(lease.ID)
		log.Printf("released lease for %s (%s)", mac, lease.IP)
	}
}

func (s *Server) handleDecline(pkt *Packet) {
	// client declined the IP, remove the lease
	mac := pkt.MAC()
	lease, _ := s.store.FindLeaseByMAC(mac)
	if lease != nil {
		s.store.DeleteLease(lease.ID)
		log.Printf("client %s declined IP %s", mac, lease.IP)
	}
}

func (s *Server) sendOffer(pkt *Packet, ip net.IP, scopeID int64) {
	scope, err := s.store.GetScope(scopeID)
	if err != nil {
		log.Printf("scope error: %v", err)
		return
	}

	reply := NewReply(pkt).
		MessageType(Offer).
		ServerID(s.serverIP).
		SubnetMask(net.IPMask(net.ParseIP(scope.SubnetMask).To4())).
		Router(net.ParseIP(scope.Gateway)).
		DNS(parseDNS(scope.DNS)).
		LeaseTime(uint32(scope.LeaseDuration)).
		Build(ip, s.serverIP)

	s.sendReply(reply, pkt)
	log.Printf("OFFER %s to %s", ip, pkt.MAC())
}

func (s *Server) sendAck(pkt *Packet, ip net.IP, scopeID int64) {
	scope, err := s.store.GetScope(scopeID)
	if err != nil {
		log.Printf("scope error: %v", err)
		return
	}

	// create/update lease
	hostname := ""
	if h, ok := pkt.Options[OptHostname]; ok {
		hostname = string(h)
	}

	lease := &store.Lease{
		ScopeID:   scopeID,
		IP:        ip.String(),
		MAC:       pkt.MAC(),
		Hostname:  hostname,
		ExpiresAt: time.Now().Add(time.Duration(scope.LeaseDuration) * time.Second),
	}
	s.store.CreateLease(lease)

	reply := NewReply(pkt).
		MessageType(Ack).
		ServerID(s.serverIP).
		SubnetMask(net.IPMask(net.ParseIP(scope.SubnetMask).To4())).
		Router(net.ParseIP(scope.Gateway)).
		DNS(parseDNS(scope.DNS)).
		LeaseTime(uint32(scope.LeaseDuration)).
		Build(ip, s.serverIP)

	s.sendReply(reply, pkt)
	log.Printf("ACK %s to %s", ip, pkt.MAC())
}

func (s *Server) sendNak(pkt *Packet) {
	reply := NewReply(pkt).
		MessageType(Nak).
		ServerID(s.serverIP).
		Build(net.IPv4zero, s.serverIP)

	s.sendReply(reply, pkt)
	log.Printf("NAK to %s", pkt.MAC())
}

func (s *Server) sendReply(reply *Packet, request *Packet) {
	data := reply.Marshal()

	var dest *net.UDPAddr
	if request.GIAddr.IsUnspecified() {
		// direct client
		if request.Flags&0x8000 != 0 {
			dest = &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
		} else {
			dest = &net.UDPAddr{IP: reply.YIAddr, Port: 68}
		}
	} else {
		// relay
		dest = &net.UDPAddr{IP: request.GIAddr, Port: 67}
	}

	s.conn.WriteToUDP(data, dest)
}

func (s *Server) allocateIP(pkt *Packet) (*store.Scope, net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// determine which scope based on relay or direct
	var targetNetwork net.IP
	if !pkt.GIAddr.IsUnspecified() {
		targetNetwork = pkt.GIAddr
	} else {
		targetNetwork = s.serverIP
	}

	scope, err := s.store.FindScopeForNetwork(targetNetwork)
	if err != nil || scope == nil {
		// try first enabled scope
		scopes, _ := s.store.GetScopes()
		for _, sc := range scopes {
			if sc.Enabled {
				scope = &sc
				break
			}
		}
	}

	if scope == nil {
		return nil, nil
	}

	used, _ := s.store.GetUsedIPs(scope.ID)

	start := net.ParseIP(scope.RangeStart).To4()
	end := net.ParseIP(scope.RangeEnd).To4()

	for ip := cloneIP(start); compareIP(ip, end) <= 0; incIP(ip) {
		ipStr := ip.String()
		if !used[ipStr] {
			return scope, ip
		}
	}

	return nil, nil
}

func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for s.running {
		<-ticker.C
		deleted, err := s.store.DeleteExpiredLeases()
		if err == nil && deleted > 0 {
			log.Printf("cleaned up %d expired leases", deleted)
		}
	}
}

// helpers

func parseDNS(dns string) []net.IP {
	var result []net.IP
	for _, d := range splitTrim(dns, ",") {
		if ip := net.ParseIP(d); ip != nil {
			result = append(result, ip)
		}
	}
	return result
}

func splitTrim(s, sep string) []string {
	var result []string
	for _, part := range split(s, sep) {
		if t := trim(part); t != "" {
			result = append(result, t)
		}
	}
	return result
}

func split(s, sep string) []string {
	if s == "" {
		return nil
	}
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep[0] {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trim(s string) string {
	start, end := 0, len(s)
	for start < end && s[start] == ' ' {
		start++
	}
	for end > start && s[end-1] == ' ' {
		end--
	}
	return s[start:end]
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

func compareIP(a, b net.IP) int {
	a4 := a.To4()
	b4 := b.To4()
	aInt := binary.BigEndian.Uint32(a4)
	bInt := binary.BigEndian.Uint32(b4)
	if aInt < bInt {
		return -1
	}
	if aInt > bInt {
		return 1
	}
	return 0
}

func msgTypeName(t byte) string {
	switch t {
	case Discover:
		return "DISCOVER"
	case Offer:
		return "OFFER"
	case Request:
		return "REQUEST"
	case Ack:
		return "ACK"
	case Nak:
		return "NAK"
	case Release:
		return "RELEASE"
	case Decline:
		return "DECLINE"
	case Inform:
		return "INFORM"
	}
	return "UNKNOWN"
}
