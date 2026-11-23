package webfilter

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name  string
		addrs []net.IPAddr
		err   error
		want  string
	}{
		{"cloudflare blocks with 0.0.0.0", []net.IPAddr{{IP: net.IPv4zero}}, nil, StateOn},
		{"blocked on both families", []net.IPAddr{{IP: net.IPv4zero}, {IP: net.IPv6unspecified}}, nil, StateOn},
		{"real address means no filter", []net.IPAddr{{IP: net.ParseIP("104.16.0.1")}}, nil, StateOff},
		{"one real address among zeros is still open", []net.IPAddr{{IP: net.IPv4zero}, {IP: net.ParseIP("2606:4700::1")}}, nil, StateOff},
		{"refused answer (NXDOMAIN) is a filter", nil, &net.DNSError{Err: "no such host", Name: TestDomain, IsNotFound: true}, StateOn},
		{"timeout is unknown, never off", nil, &net.DNSError{Err: "i/o timeout", Name: TestDomain, IsTimeout: true}, StateUnknown},
		{"no network is unknown", nil, errors.New("network is unreachable"), StateUnknown},
	}
	for _, c := range cases {
		if got := classify(c.addrs, c.err).State; got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestCheckUsesTheTestDomain(t *testing.T) {
	old := lookupFn
	t.Cleanup(func() { lookupFn = old })
	var asked string
	lookupFn = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		asked = host
		return []net.IPAddr{{IP: net.IPv4zero}}, nil
	}
	status := Check(context.Background())
	if asked != TestDomain || status.State != StateOn || status.CheckedAt.IsZero() {
		t.Fatalf("asked %q, got %+v", asked, status)
	}
}

func TestWatchTellsOnceWhenItIsTurnedOff(t *testing.T) {
	dir := t.TempDir()
	on, off := Status{State: StateOn}, Status{State: StateOff}
	// Never on: off is not news (the window shows it), nothing to tell.
	if tell, _ := Watch(dir, off); tell {
		t.Fatal("told off on a computer where it was never on")
	}
	Watch(dir, on)
	if tell, _ := Watch(dir, off); !tell {
		t.Fatal("not told when it went from on to off")
	}
	for i := 0; i < 3; i++ {
		if tell, _ := Watch(dir, off); tell {
			t.Fatalf("told again on check %d", i)
		}
	}
	// Unknown (no network) changes nothing.
	if tell, _ := Watch(dir, Status{State: StateUnknown}); tell {
		t.Fatal("unknown told")
	}
	// Back on, then off again: told once more.
	Watch(dir, on)
	if tell, _ := Watch(dir, off); !tell {
		t.Fatal("second time off was not told")
	}
}

func TestTurnOffWithoutTheAgentsChangeExplains(t *testing.T) {
	if err := TurnOff(t.TempDir()); err == nil {
		t.Fatal("undo without a saved backup must refuse")
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("Bob's Wi-Fi"); got != `'Bob'\''s Wi-Fi'` {
		t.Fatal(got)
	}
}
