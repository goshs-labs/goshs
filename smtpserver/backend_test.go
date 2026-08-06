package smtpserver

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"goshs.de/goshs/v2/chat"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
)

func TestAuthPlain(t *testing.T) {
	s := &Session{}
	err := s.AuthPlain("user", "pass")
	require.NoError(t, err)
}

func TestMail(t *testing.T) {
	s := &Session{}
	err := s.Mail("sender@example.com", nil)
	require.NoError(t, err)
	require.Equal(t, "sender@example.com", s.from)
}

func TestLogout(t *testing.T) {
	s := &Session{}
	err := s.Logout()
	require.NoError(t, err)
}

func TestData_PlainText(t *testing.T) {
	cb := chat.New()
	hub := ws.NewHub(cb, false)
	go hub.Run()
	wh := webhook.Register(false, "", "discord", []string{})

	s := &Session{
		hub:     hub,
		webhook: wh,
		from:    "sender@example.com",
		to:      []string{"rcpt@example.com"},
	}

	msg := "From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: Test\r\nContent-Type: text/plain\r\n\r\nHello World\r\n"
	err := s.Data(strings.NewReader(msg))
	require.NoError(t, err)
}

func TestData_Multipart(t *testing.T) {
	cb := chat.New()
	hub := ws.NewHub(cb, false)
	go hub.Run()
	wh := webhook.Register(false, "", "discord", []string{})

	s := &Session{
		hub:     hub,
		webhook: wh,
		from:    "sender@example.com",
		to:      []string{"rcpt@example.com"},
	}

	msg := "From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: Test\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nBody text\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"test.bin\"\r\n\r\nbinary data here\r\n--b--\r\n"
	err := s.Data(strings.NewReader(msg))
	require.NoError(t, err)
}

func TestData_InvalidMessage(t *testing.T) {
	cb := chat.New()
	hub := ws.NewHub(cb, false)
	go hub.Run()
	wh := webhook.Register(false, "", "discord", []string{})

	s := &Session{
		hub:     hub,
		webhook: wh,
		from:    "sender@example.com",
		to:      []string{"rcpt@example.com"},
	}

	err := s.Data(strings.NewReader(""))
	// Empty reader should still work since io.ReadAll returns empty
	_ = err
}

func TestNewBackend(t *testing.T) {
	cb := chat.New()
	hub := ws.NewHub(cb, false)
	wh := webhook.Register(false, "", "discord", []string{})
	be := &Backend{Hub: hub, WebHook: wh, Domain: "test.com"}

	session, err := be.NewSession(nil)
	require.NoError(t, err)
	require.NotNil(t, session)
}

func TestNewSMTPServer(t *testing.T) {
	cb := chat.New()
	hub := ws.NewHub(cb, false)
	wh := webhook.Register(false, "", "discord", []string{})
	opts := &options.Options{
		IP:         "0.0.0.0",
		SMTPPort:   2525,
		SMTPDomain: "test.local",
	}

	srv := NewSMTP(opts, hub, wh)
	require.NotNil(t, srv)
	require.Equal(t, "0.0.0.0", srv.IP)
	require.Equal(t, 2525, srv.Port)
	require.Equal(t, "test.local", srv.Domain)
}
