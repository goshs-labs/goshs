package dnsserver

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"goshs.de/goshs/v2/chat"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
)

func newTestServer() *DNSServer {
	cb := chat.New()
	hub := ws.NewHub(cb, false)
	go hub.Run()
	wh := webhook.Register(false, "", "discord", []string{})
	return &DNSServer{
		IP:      "127.0.0.1",
		ReplyIP: "1.2.3.4",
		Port:    0, // not binding
		Hub:     hub,
		WebHook: wh,
	}
}

func TestNewDNSServer_Fields(t *testing.T) {
	cb := chat.New()
	hub := ws.NewHub(cb, false)
	go hub.Run()
	wh := webhook.Register(false, "", "discord", []string{})

	opts := &options.Options{
		DNSIP:   "10.0.0.1",
		DNSPort: 5353,
	}

	s := NewDNSServer(opts, hub, wh)
	require.Equal(t, "0.0.0.0", s.IP)
	require.Equal(t, "10.0.0.1", s.ReplyIP)
	require.Equal(t, 5353, s.Port)
}

// mockResponseWriter implements dns.ResponseWriter for testing the handler
// without starting a real UDP/TCP listener.
type mockResponseWriter struct {
	written *dns.Msg
	remote  string
}

func (m *mockResponseWriter) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (m *mockResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}
func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error { m.written = msg; return nil }
func (m *mockResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockResponseWriter) Close() error                { return nil }
func (m *mockResponseWriter) TsigStatus() error           { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool)         {}
func (m *mockResponseWriter) Hijack()                     {}

func TestDNSHandler_ARecord(t *testing.T) {
	s := newTestServer()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	w := &mockResponseWriter{}
	s.handler(w, req)

	require.NotNil(t, w.written)
	require.True(t, w.written.Authoritative)
	require.Len(t, w.written.Answer, 1)

	a, ok := w.written.Answer[0].(*dns.A)
	require.True(t, ok, "answer should be A record")
	require.Equal(t, "1.2.3.4", a.A.String())
}

func TestDNSHandler_MXRecord(t *testing.T) {
	s := newTestServer()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeMX)

	w := &mockResponseWriter{}
	s.handler(w, req)

	require.NotNil(t, w.written)
	require.Len(t, w.written.Answer, 1)

	mx, ok := w.written.Answer[0].(*dns.MX)
	require.True(t, ok, "answer should be MX record")
	require.Equal(t, uint16(10), mx.Preference)
	require.Equal(t, "mail.example.com.", mx.Mx)
}

func TestDNSHandler_TXTRecord(t *testing.T) {
	s := newTestServer()

	req := new(dns.Msg)
	req.SetQuestion("callback.example.com.", dns.TypeTXT)

	w := &mockResponseWriter{}
	s.handler(w, req)

	require.NotNil(t, w.written)
	require.Len(t, w.written.Answer, 1)

	txt, ok := w.written.Answer[0].(*dns.TXT)
	require.True(t, ok, "answer should be TXT record")
	require.Equal(t, "callback.example.com.", txt.Txt[0])
	require.True(t, strings.HasPrefix(txt.Txt[1], "src="), "second TXT string should carry src= attribution")
}

func TestDNSHandler_UnknownType_NoAnswer(t *testing.T) {
	s := newTestServer()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeNS) // NS is not handled

	w := &mockResponseWriter{}
	s.handler(w, req)

	require.NotNil(t, w.written)
	require.Empty(t, w.written.Answer)
}

func TestDNSHandler_MultipleQuestions(t *testing.T) {
	s := newTestServer()

	req := new(dns.Msg)
	req.Question = []dns.Question{
		{Name: "a.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "b.example.com.", Qtype: dns.TypeMX, Qclass: dns.ClassINET},
	}

	w := &mockResponseWriter{}
	s.handler(w, req)

	require.NotNil(t, w.written)
	require.Len(t, w.written.Answer, 2)
}

func TestDNSHandler_ReplyIPFallback(t *testing.T) {
	// When opts.DNSIP is empty, NewDNSServer should default ReplyIP to "0.0.0.0".
	cb := chat.New()
	hub := ws.NewHub(cb, false)
	go hub.Run()
	wh := webhook.Register(false, "", "discord", []string{})

	opts := &options.Options{DNSIP: ""} // empty — constructor should default to 0.0.0.0
	s := NewDNSServer(opts, hub, wh)

	req := new(dns.Msg)
	req.SetQuestion("test.local.", dns.TypeA)

	w := &mockResponseWriter{}
	s.handler(w, req)

	require.NotNil(t, w.written)
	require.Len(t, w.written.Answer, 1)
	a := w.written.Answer[0].(*dns.A)
	require.Equal(t, "0.0.0.0", a.A.String())
}
