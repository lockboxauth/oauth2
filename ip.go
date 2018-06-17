package oauth2

import (
	"net"
	"net/http"
	"strings"
)

var (
	cidrs       []*net.IPNet
	stringCIDRs = [...]string{"127.0.0.1/8", "10.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"}
)

func init() {
	cidrs = make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range stringCIDRs {
		_, netCIDR, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		cidrs = append(cidrs, netCIDR)
	}
}

// isLocal returns true if an IP should be considered local.
func isLocal(addr string) bool {
	a := net.ParseIP(addr)
	for _, cidr := range cidrs {
		if cidr.Contains(a) {
			return true
		}
	}
	return false
}

// remoteAddr returns the IP portion of the RemoteAddr of the
// passed request, discarding any port.
func remoteAddr(r *http.Request) string {
	addr := strings.TrimSpace(r.RemoteAddr)
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return addr
	}
	return addr[:lastColon]
}

// getIP returns a best guess at the IP a request came from.
func getIP(r *http.Request) string {
	realIP := r.Header.Get("X-Real-Ip")
	forwardedFor := r.Header.Get("X-Forwarded-For")

	if len(realIP) == 0 && len(forwardedFor) == 0 {
		return remoteAddr(r)
	}

	for _, addr := range strings.Split(forwardedFor, ", ") {
		addr = strings.TrimSpace(addr)
		if len(addr) == 0 {
			continue
		}
		if isLocal(addr) {
			continue
		}
		return addr
	}

	return realIP
}
