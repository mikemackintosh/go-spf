package spf

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	RESULT_SOFTFAIL = "softfail"
	RESULT_FAIL     = "fail"
	RESULT_NEUTRAL  = "neutral"
	RESULT_PASS     = "pass"
)

var (
	resolver = &net.Resolver{PreferGo: true}

	resultMap = map[string]string{
		"~all": RESULT_SOFTFAIL,
		"-all": RESULT_FAIL,
		// "?":    RESULT_PASS,
		// "+":    RESULT_PASS,
	}
)

// SpfRecord is an object containing the SPF record and its associated
// information like domain, policy, version, etc.
type SpfRecord struct {
	Version   string
	Domain    string
	Policy    string
	Record    string
	Includes  []*SpfRecord
	Allowlist []*SpfEntry
	Errors    []error
}

// SpfEntry is a IP network based collection of subnets, IPv4, and IPv6.
type SpfEntry struct {
	Entry   string
	Network []net.IPNet
}

// Include will append the results of an include statement. These are collected,
// evaluated then parsed into an allowlist for decision making.
func (s *SpfRecord) Include(inc *SpfRecord) {
	s.Includes = append(s.Includes, inc)
}

// Validate will loop through all allowed network blocks and match on the provided IP.
// It will return pass, fail, softfail, neutral in the first argument
// Second argument returns true or false if there is a match.
func (s *SpfRecord) Validate(ip string) (string, bool) {
	for _, a := range s.Allowlist {
		for _, subnet := range a.Network {
			if subnet.Contains(net.ParseIP(ip)) {
				return RESULT_PASS, true
			}
		}
	}

	return resultMap[s.Policy], false
}

// SpfIncludes is a collection of SpfInclude.
type SpfIncludes []*SpfInclude
type SpfInclude struct {
	Entry    string
	Hosts    []string
	Networks []net.IPNet
	IPs      []net.IP
}

// SetResolver takes an IP address that you want to use as the default resolved. Otherwise, this will use the default resolver of the system, which could be mDNSResponder, /etc/resolv.conf or other medium.
func SetResolver(listener string) error {
	listenerParts := strings.Split(listener, ":")
	var ip = net.ParseIP(listenerParts[0])
	if ip == nil {
		return ErrDNSInvalidResolver{listener}
	}

	resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(1500),
			}
			return d.DialContext(ctx, network, listener)
		},
	}

	return nil
}

// Get takes a domain and returns an evaluated SpfRecord and Error.
func Get(domain string) (*SpfRecord, error) {
	var err error

	// Get the SpfEntry
	spf, err := GetSpfEntry(domain)
	if err != nil {
		return spf, err
	}

	// Time to aggregate the allowlist from all the children includes.
	spf.Allowlist = AggregateAllowlist(spf)

	return spf, nil
}

// AggregateAllowlist will loop through all the SpfIncludes recursively and
// add all the allowed networks to the Allowlist field.
func AggregateAllowlist(spf *SpfRecord) []*SpfEntry {
	var ret = []*SpfEntry{}

	for _, i := range spf.Includes {
		ret = append(ret, AggregateAllowlist(i)...)
	}

	ret = append(ret, spf.Allowlist...)

	return ret
}

// NewSpfRecord will create and return a new pointer to an SpfRecord struct.
// By default, it will add the domain to the Domain field, and an empty list
// of SpfIncludes.
func NewSpfRecord(domain string) *SpfRecord {
	var spf = SpfRecord{
		Domain:    domain,
		Policy:    RESULT_NEUTRAL,
		Includes:  []*SpfRecord{},
		Allowlist: []*SpfEntry{},
		Errors:    []error{},
	}

	return &spf
}

// GetSpfEntry will query DNS and return a SPF record entry prefixed with `v=spf1`.
// The response is an error or a pointer to SpfRecord
func GetSpfEntry(domain string) (*SpfRecord, error) {
	var spf = NewSpfRecord(domain)

	var txtRecords, err = ResolveTXT(domain)
	if err != nil {
		return spf, err
	}

	// Loop through records
	for _, value := range txtRecords {
		if strings.Contains(value, "v=spf1") {
			spf.Record = value
		}
	}

	// We did not find a record
	if spf.Record == "" {
		return spf, ErrSPFRecordNotFound{domain}
	}

	_, err = ParseSPF(spf)
	if err != nil {
		return spf, err
	}

	return spf, nil
}

// ParseSPF is the meat and potatoes as it evaluates the returned SPF record.
// It will recursively evaluate include: statements.
//
// @TODO: Add support for exists and +/? predicates.
func ParseSPF(spf *SpfRecord) (*SpfRecord, error) {
	// fmt.Printf("=> Looking into %s (%s)\n", spf.Domain, spf.Record)
	// Split the record so we can expand hsots
	recordParts := strings.Split(spf.Record, " ")

	// Check the length
	if len(recordParts) <= 2 {
		return spf, ErrSPFRecordInvalid{spf.Domain, spf.Record}
	}

	// Get the policy
	spf.Policy = recordParts[len(recordParts)-1]

	// Loop through the networks
	for _, p := range recordParts {
		// Set Version only if it's not set
		if spf.Version == "" && strings.Contains(p, "v=") {
			spf.Version = p
		}

		if strings.Contains(p, "ip4:") {
			var ip = p[4:]
			var mask = net.CIDRMask(32, 32)
			if strings.Contains(p[4:], "/") {
				s := strings.Split(p[4:], "/")
				cidr, _ := strconv.Atoi(s[1])
				ip = s[0]
				mask = net.CIDRMask(cidr, 32)
			}

			entry := &SpfEntry{
				Entry: p,
				Network: []net.IPNet{
					net.IPNet{
						IP:   net.ParseIP(ip),
						Mask: mask,
					},
				},
			}

			spf.Allowlist = append(spf.Allowlist, entry)
		}

		if strings.Contains(p, "ip6:") {
			var ip = p[4:]
			var mask = net.CIDRMask(128, 128)
			if strings.Contains(p[4:], "/") {
				s := strings.Split(p[4:], "/")
				cidr, _ := strconv.Atoi(s[1])
				ip = s[0]
				mask = net.CIDRMask(cidr, 128)
			}

			entry := &SpfEntry{
				Entry: p,
				Network: []net.IPNet{
					net.IPNet{
						IP:   net.ParseIP(ip),
						Mask: mask,
					},
				},
			}

			spf.Allowlist = append(spf.Allowlist, entry)
		}

		//Check for include segments, so we can resolve and append for later searching.
		if strings.Contains(p, "include:") {
			includeSpf, err := GetSpfEntry(p[8:])
			if err != nil {
				spf.Errors = append(spf.Errors, err)
			}

			// fmt.Printf("includeSpf: %+v\n", includeSpf)
			spf.Include(includeSpf)
		}

		/*
			// TODO: add exists: support
			if strings.Contains(p, "exists:") {
			  spf.Version = p
			}
		*/

		// If mx is present, resolve MX
		if p == "mx" {
			ips, err := ResolveMXToIPs(spf.Domain)
			if err != nil {
				spf.Errors = append(spf.Errors, err)
			}

			var networks []net.IPNet
			for _, ip := range ips {
				networks = append(networks, net.IPNet{
					IP: ip,
				})
			}

			entry := &SpfEntry{
				Entry:   p,
				Network: networks,
			}

			spf.Allowlist = append(spf.Allowlist, entry)
		}

		if p == "a" {
			ips, err := ResolveA(spf.Domain)
			if err != nil {
				spf.Errors = append(spf.Errors, err)
			}

			var networks []net.IPNet
			for _, ip := range ips {
				networks = append(networks, net.IPNet{
					IP: ip,
				})
			}

			entry := &SpfEntry{
				Entry:   p,
				Network: networks,
			}

			spf.Allowlist = append(spf.Allowlist, entry)
		}
	}

	// fmt.Printf("spf for %s has %d/%d records\n", spf.Domain, len(spf.Includes), len(spf.Allowlist))

	return spf, nil
}

// ResolveTXT is a wrapper for resolving TXT records.
func ResolveTXT(domain string) ([]string, error) {
	return resolver.LookupTXT(context.Background(), domain)
}

// ResolveA is a wrapper for resolving a Host/A record.
func ResolveA(host string) ([]net.IP, error) {
	var ips = []net.IP{}
	results, _ := resolver.LookupIPAddr(context.Background(), host)
	for _, ip := range results {
		ips = append(ips, ip.IP)
	}
	return ips, nil
}

// ResolveMXToIPs will resolve MX records to hostnames, and in turn to IP's.
func ResolveMXToIPs(host string) ([]net.IP, error) {
	mx, err := resolver.LookupMX(context.Background(), host)
	var ips = []net.IP{}
	for _, r := range mx {
		// TODO: check for IP in returned output and resolve.
		if ip, err := ResolveA(r.Host); err == nil {
			ips = append(ips, ip...)
		}
	}

	return ips, err
}
