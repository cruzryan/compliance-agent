//go:build windows

package webfilter

import "testing"

func TestCleanErrorTextReadsCLIXML(t *testing.T) {
	raw := "#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><Obj S=\"progress\"></Obj><S S=\"Error\">Access is denied._x000D__x000A_</S></Objs>"
	if got := cleanErrorText(raw); got != "Access is denied." {
		t.Fatalf("got %q", got)
	}
	if got := cleanErrorText("plain text error\n"); got != "plain text error" {
		t.Fatalf("got %q", got)
	}
}
