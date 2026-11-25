package utils

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Regression tests for GHSA-qjjr-pc25-pj69: a bcrypt -b secret is verified as a
// hash; the hash string itself is never accepted as the password.

func TestCheckPasswordPlaintext(t *testing.T) {
	if !CheckPassword("s3cret", "s3cret") {
		t.Fatal("plaintext password must match itself")
	}
	if CheckPassword("s3cret", "S3cret") {
		t.Fatal("wrong plaintext password must not match")
	}
}

func TestCheckPasswordBcryptHash(t *testing.T) {
	for _, prefix := range []string{"$2a$", "$2b$", "$2y$"} {
		raw, err := bcrypt.GenerateFromPassword([]byte("S3cret-pass"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		hash := prefix + string(raw[4:])
		if !IsBcryptHash(hash) {
			t.Fatalf("%s: not recognised as bcrypt", prefix)
		}
		if !CheckPassword(hash, "S3cret-pass") {
			t.Fatalf("%s: the real password must match its bcrypt hash", prefix)
		}
		if CheckPassword(hash, hash) {
			t.Fatalf("%s: the hash string itself must not be accepted as the password", prefix)
		}
		if CheckPassword(hash, "wrong") {
			t.Fatalf("%s: a wrong password must not match", prefix)
		}
	}
}
