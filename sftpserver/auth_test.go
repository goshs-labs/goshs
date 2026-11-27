package sftpserver

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// Regression test for GHSA-qjjr-pc25-pj69: with a bcrypt -b secret, SFTP must
// accept the real password and refuse the hash string.
func TestCheckPassword_BcryptHash(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("S3cret-pass"), bcrypt.MinCost)
	require.NoError(t, err)
	s := &SFTPServer{Username: "operator", Password: string(hash)}

	require.True(t, s.checkPassword("operator", "S3cret-pass"))
	require.False(t, s.checkPassword("operator", string(hash)), "the hash must not work as the password")
	require.False(t, s.checkPassword("other", "S3cret-pass"))
}

func TestCheckPassword_Plaintext(t *testing.T) {
	s := &SFTPServer{Username: "operator", Password: "S3cret-pass"}
	require.True(t, s.checkPassword("operator", "S3cret-pass"))
	require.False(t, s.checkPassword("operator", "wrong"))
}

// GHSA-hhv7-wp66-4vfv: -b 'user:' must not let the username log in with an
// empty password.
func TestCheckPassword_EmptyConfiguredPasswordNeverAuthenticates(t *testing.T) {
	s := &SFTPServer{Username: "user", Password: ""}
	require.False(t, s.checkPassword("user", ""))
	require.False(t, s.checkPassword("user", "anything"))
}
