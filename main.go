package main

import (
	"bufio"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	cnIPv4Nets []*net.IPNet
)

// DNS cache entry with expiration
type cacheEntry struct {
	response  *dns.Msg
	expiresAt time.Time
}

// DNS response cache with concurrent access support
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
}

func newDNSCache() *dnsCache {
	return &dnsCache{
		entries: make(map[string]*cacheEntry),
	}
}

// Get cached response if not expired
func (c *dnsCache) Get(key string) (*dns.Msg, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.response.Copy(), true
}

// Set cache entry with TTL
func (c *dnsCache) Set(key string, resp *dns.Msg, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		response:  resp.Copy(),
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

// Clean expired entries
func (c *dnsCache) CleanExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}

var cache = newDNSCache()

func loadIPList(path string) ([]*net.IPNet, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var nets []*net.IPNet
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			log.Printf("invalid CIDR skipped: %s\n", line)
			continue
		}
		nets = append(nets, ipNet)
	}
	return nets, scanner.Err()
}

// Check if IP is in the given network list
func isInIPNets(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Query upstream DNS server.
func queryDNS(r *dns.Msg, server string) (*dns.Msg, error) {
	c := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
	}
	resp, _, err := c.Exchange(r, server)
	return resp, err
}

// Get minimum TTL from DNS response
func getMinTTL(resp *dns.Msg) uint32 {
	if resp == nil || len(resp.Answer) == 0 {
		return 300 // Default 5 minutes
	}

	minTTL := uint32(3600) // Max 1 hour
	for _, ans := range resp.Answer {
		if ans.Header().Ttl < minTTL {
			minTTL = ans.Header().Ttl
		}
	}

	// Ensure minimum TTL of 60 seconds
	if minTTL < 60 {
		minTTL = 60
	}
	return minTTL
}

// Generate cache key from DNS question
func getCacheKey(r *dns.Msg) string {
	if len(r.Question) == 0 {
		return ""
	}
	q := r.Question[0]
	return q.Name + ":" + dns.TypeToString[q.Qtype]
}

func filterIPv6AndPickIPv4(rrs []dns.RR, match func(net.IP) bool) ([]dns.RR, int) {
	filtered := make([]dns.RR, 0, len(rrs))
	matchedIPv4 := 0

	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			if match == nil || match(v.A) {
				filtered = append(filtered, rr)
				matchedIPv4++
			}
		case *dns.AAAA:
			continue
		default:
			filtered = append(filtered, rr)
		}
	}

	return filtered, matchedIPv4
}

func buildFilteredResponse(req *dns.Msg, upstream *dns.Msg, match func(net.IP) bool) (*dns.Msg, int) {
	if upstream == nil {
		return nil, 0
	}

	filtered := upstream.Copy()
	filtered.Id = req.Id

	var matchedIPv4 int
	filtered.Answer, matchedIPv4 = filterIPv6AndPickIPv4(upstream.Answer, match)
	filtered.Ns, _ = filterIPv6AndPickIPv4(upstream.Ns, nil)
	filtered.Extra, _ = filterIPv6AndPickIPv4(upstream.Extra, nil)

	return filtered, matchedIPv4
}

func writeServFail(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeServerFailure)
	w.WriteMsg(resp)
}

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	primaryDNS := "119.29.29.29:53"
	fallbackDNS := "1.1.1.1:53"

	// Check cache first
	cacheKey := getCacheKey(r)
	if cacheKey != "" {
		if cachedResp, found := cache.Get(cacheKey); found {
			log.Printf("Cache hit for %s", cacheKey)
			cachedResp.Id = r.Id // Update message ID to match request
			w.WriteMsg(cachedResp)
			return
		}
	}

	// Query primary DNS first
	resp, err := queryDNS(r, primaryDNS)
	if err != nil {
		log.Printf("primary DNS failed: %v, fallback to %s\n", err, fallbackDNS)
		resp, err = queryDNS(r, fallbackDNS)
		if err != nil || resp == nil {
			log.Printf("fallback DNS failed: %v", err)
			writeServFail(w, r)
			return
		}
		filteredFallback, _ := buildFilteredResponse(r, resp, nil)
		if cacheKey != "" {
			cache.Set(cacheKey, filteredFallback, getMinTTL(filteredFallback))
		}
		w.WriteMsg(filteredFallback)
		return
	}

	filteredPrimary, matchedIPv4 := buildFilteredResponse(r, resp, func(ip net.IP) bool {
		return isInIPNets(ip, cnIPv4Nets)
	})
	if matchedIPv4 > 0 {
		if cacheKey != "" {
			cache.Set(cacheKey, filteredPrimary, getMinTTL(filteredPrimary))
		}
		w.WriteMsg(filteredPrimary)
		return
	}

	log.Printf("no primary IPv4 match in CN list, fallback to %s", fallbackDNS)
	fallbackResp, err := queryDNS(r, fallbackDNS)
	if err != nil || fallbackResp == nil {
		log.Printf("fallback DNS failed: %v", err)
		writeServFail(w, r)
		return
	}

	filteredFallback, _ := buildFilteredResponse(r, fallbackResp, nil)
	if cacheKey != "" {
		cache.Set(cacheKey, filteredFallback, getMinTTL(filteredFallback))
	}
	w.WriteMsg(filteredFallback)
}

func main() {
	var err error
	cnIPv4Nets, err = loadIPList("cn-ipv4.list")
	if err != nil {
		log.Fatalf("failed to load cn-ipv4.list: %v", err)
	}

	// Start cache cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cache.CleanExpired()
			log.Println("Cache cleanup completed")
		}
	}()

	dns.HandleFunc(".", handleDNS)

	// UDP
	go func() {
		server := &dns.Server{
			Addr: "127.0.0.21:53",
			Net:  "udp",
		}
		log.Println("DNS server started on UDP 127.0.0.21:53")
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("UDP server failed: %v", err)
		}
	}()

	// TCP
	server := &dns.Server{
		Addr: "127.0.0.21:53",
		Net:  "tcp",
	}
	log.Println("DNS server started on TCP 127.0.0.21:53")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("TCP server failed: %v", err)
	}
}
