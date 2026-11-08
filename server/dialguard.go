package server

import (
	"net"
	"strconv"
	"strings"
)

// Shared SSRF guards for the endpoints that fetch a URL the user supplied:
// the egress probe and the request repeater. They live together because the
// rule they encode must be the same in both — a hole opened in one copy is a
// hole in the product.

// isBlockedDialIP reports whether an address must never be dialled on behalf
// of a user-supplied URL: loopback and link-local reach ARTEX itself and the
// cloud metadata service (169.254.169.254), and multicast/unspecified are not
// meaningful destinations. A nil IP is blocked — an address we cannot classify
// is not an address we dial.
//
// RFC1918 ranges are deliberately NOT blocked. The point of a custom probe
// endpoint is usually an intranet echo service, and blocking 10/8, 172.16/12
// and 192.168/16 would remove the feature.
func isBlockedDialIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// looksNumericHost reports whether a host could be one of inet_aton's numeric
// IPv4 spellings — decimal, octal or hex, in 1 to 4 parts. net.ParseIP rejects
// all but dotted-quad, so without this check "http://0x7f.1" or
// "http://2130706433" would be treated as a DNS name and sail past a loopback
// test, only to resolve to 127.0.0.1 at dial time.
func looksNumericHost(host string) bool {
	if host == "" || host[0] < '0' || host[0] > '9' {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		switch {
		case c == '.':
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		case c == 'x' || c == 'X':
		default:
			return false
		}
	}
	return true
}

// parseLegacyIPv4 follows inet_aton's 1-, 2-, 3- and 4-part IPv4 notation.
// Parts with a leading zero are octal and parts with 0x are hex.
func parseLegacyIPv4(host string) (net.IP, bool) {
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return nil, false
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" {
			return nil, false
		}
		base := 10
		digits := part
		if len(digits) > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X') {
			base, digits = 16, digits[2:]
		} else if len(digits) > 1 && digits[0] == '0' {
			base = 8
		}
		if digits == "" {
			return nil, false
		}
		value, err := strconv.ParseUint(digits, base, 32)
		if err != nil {
			return nil, false
		}
		values[i] = value
	}
	// The last part absorbs the remaining octets: "127.1" is 127.0.0.1 and
	// "2130706433" is the whole address in one number.
	var value uint64
	switch len(values) {
	case 1:
		value = values[0]
	case 2:
		if values[0] > 0xff || values[1] > 0xffffff {
			return nil, false
		}
		value = values[0]<<24 | values[1]
	case 3:
		if values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff {
			return nil, false
		}
		value = values[0]<<24 | values[1]<<16 | values[2]
	case 4:
		for _, part := range values {
			if part > 0xff {
				return nil, false
			}
		}
		value = values[0]<<24 | values[1]<<16 | values[2]<<8 | values[3]
	}
	if value > 0xffffffff {
		return nil, false
	}
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value)), true
}
