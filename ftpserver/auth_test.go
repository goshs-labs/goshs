package ftpserver

import (
	"net"
	"testing"

	ftplib "github.com/fclairamb/ftpserverlib"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"goshs.de/goshs/v2/webhook"
)

type fakeClientContext struct{ ftplib.ClientContext }

func (fakeClientContext) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}
}

// Regression test for GHSA-qjjr-pc25-pj69: with a bcrypt -b secret, FTP must
// accept the real password and refuse the hash string.
func TestAuthUser_BcryptHash(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("S3cret-pass"), bcrypt.MinCost)
	require.NoError(t, err)
	d := &mainDriver{srv: &FTPServer{Webhook: *webhook.Register(false, "", "discord", nil), Root: t.TempDir(), Username: "operator", Password: string(hash)}}

	_, err = d.AuthUser(fakeClientContext{}, "operator", "S3cret-pass")
	require.NoError(t, err, "the real password must log in")
	_, err = d.AuthUser(fakeClientContext{}, "operator", string(hash))
	require.Error(t, err, "the hash must not work as the password")
}

func TestAuthUser_Plaintext(t *testing.T) {
	d := &mainDriver{srv: &FTPServer{Webhook: *webhook.Register(false, "", "discord", nil), Root: t.TempDir(), Username: "operator", Password: "S3cret-pass"}}
	_, err := d.AuthUser(fakeClientContext{}, "operator", "S3cret-pass")
	require.NoError(t, err)
	_, err = d.AuthUser(fakeClientContext{}, "operator", "wrong")
	require.Error(t, err)
}
