//go:build windows

package webfilter

import (
	"context"
	"errors"
	"net"
	"syscall"
	"unsafe"
)

// On Windows the check asks Windows' own DNS service (DnsQuery), the path
// browsers take. Go's own resolver sends plain lookups itself and skips
// Windows' encrypted DNS, so it reported "unknown" on a machine that was
// filtering through DNS over HTTPS, and on a redirecting network it would
// have kept reading the router's answer after the filter was on (found by
// the webfilter-windows CI job, 23 Nov 2026).
func init() { lookupFn = systemLookup }

const (
	dnsTypeA        = 0x0001
	dnsQueryNoCache = 0x00000008 // DNS_QUERY_BYPASS_CACHE: never an answer from before the change
	dnsNameError    = syscall.Errno(9003)
	dnsNoRecords    = syscall.Errno(9501)
)

func systemLookup(ctx context.Context, host string) ([]net.IPAddr, error) {
	type answer struct {
		addrs []net.IPAddr
		err   error
	}
	done := make(chan answer, 1)
	go func() {
		addrs, err := dnsQueryA(host)
		done <- answer{addrs, err}
	}()
	select {
	case a := <-done:
		return a.addrs, a.err
	case <-ctx.Done():
		return nil, &net.DNSError{Err: "timeout", Name: host, IsTimeout: true}
	}
}

func dnsQueryA(host string) ([]net.IPAddr, error) {
	var records *syscall.DNSRecord
	err := syscall.DnsQuery(host, dnsTypeA, dnsQueryNoCache, nil, &records, nil)
	if records != nil {
		defer syscall.DnsRecordListFree(records, 1)
	}
	if err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			switch errno {
			case dnsNameError:
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			case dnsNoRecords:
				return nil, nil
			}
		}
		return nil, &net.DNSError{Err: err.Error(), Name: host}
	}
	var addrs []net.IPAddr
	for r := records; r != nil; r = r.Next {
		if r.Type != dnsTypeA || r.Length < 4 {
			continue
		}
		ip := *(*[4]byte)(unsafe.Pointer(&r.Data[0]))
		addrs = append(addrs, net.IPAddr{IP: net.IPv4(ip[0], ip[1], ip[2], ip[3])})
	}
	return addrs, nil
}
