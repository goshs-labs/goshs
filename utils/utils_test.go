package utils

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	cssCorrectMime       string = "text/css; charset=utf-8"
	jsCorrectMime        string = "text/javascript; charset=utf-8"
	htmlCorrectMime      string = "text/html; charset=utf-8"
	jpgCorretMime        string = "image/jpeg"
	correctExt           string = ".txt"
	filename             string = "test.csv.txt"
	loopbackInterface    string = "lo"
	loopbackInterfaceMac string = "lo0"
	correctIP                   = "127.0.0.1"
)

func TestByteCountDecimal(t *testing.T) {
	res100 := ByteCountDecimal(100)
	if res100 != "100 B" {
		t.Errorf("Error in ByteCountDecimal, got: %s  - want %s", res100, "100 B")
	}

	res1024 := ByteCountDecimal(1024)
	if res1024 != "1.0 kB" {
		t.Errorf("Error in ByteCountDecimal, got: %s  - want %s", res1024, "1.0 kB")
	}

	res1024000 := ByteCountDecimal(1024000)
	if res1024000 != "1.0 MB" {
		t.Errorf("Error in ByteCountDecimal, got: %s  - want %s", res1024000, "1.0 MB")
	}

	res1024000000 := ByteCountDecimal(1024000000)
	if res1024000000 != "1.0 GB" {
		t.Errorf("Error in ByteCountDecimal, got: %s  - want %s", res1024000000, "1.0 GB")
	}
}
func TestMimeByExtension(t *testing.T) {
	tests := []struct {
		filename string
		expected string
	}{
		{"file.txt", "text/plain"},
		{"index.html", "text/html"},
		{"style.css", "text/css"},
		{"script.js", "text/javascript"},
		{"image.jpg", "image/jpeg"},
		{"archive.zip", "application/zip"},
		{"unknownfile", ""},
		{"", ""},
	}

	for _, test := range tests {
		actual := MimeByExtension(test.filename)
		require.True(t, strings.HasPrefix(actual, test.expected), "failed on %s: got %s", test.filename, actual)
	}
}

func TestReturnExt(t *testing.T) {
	ext := ReturnExt(filename)
	if ext != correctExt {
		t.Errorf("Error in ReturnExt: want %s - got %s", correctExt, ext)
	}

	tests := []struct {
		name     string
		expected string
	}{
		{"test.csv.txt", ".txt"},
		{"archive.tar.gz", ".gz"},
		{"README", ""},
		{"png", ""},
		{"", ""},
		{".bashrc", ".bashrc"},
		{"trailing.", "."},
		{"dir.v2/README", ""},
	}

	for _, test := range tests {
		require.Equal(t, test.expected, ReturnExt(test.name), "failed on %q", test.name)
	}
}

func TestGetIPv4Addr(t *testing.T) {
	os := runtime.GOOS
	var lo string
	if os == "darwin" {
		lo = loopbackInterfaceMac
	} else {
		lo = loopbackInterface
	}
	res, err := GetInterfaceIpv4Addr(lo)
	if err != nil {
		t.Fatal(err)
	}
	if res != correctIP {
		t.Errorf("Error in GetIPv4Addr: want %s - got %s", correctIP, res)
	}

	// Test invalid interface
	addr, err := GetInterfaceIpv4Addr("foobar0")
	require.Error(t, err)
	require.Empty(t, addr)
}

func TestGenerateHashedPassword(t *testing.T) {
	password := []byte("test1234")

	result := GenerateHashedPassword(password)

	if !strings.HasPrefix(result, "$2a$14$") {
		t.Errorf("Error in GenerateHashedPassword: want suffix $2a$14$ - got: %s", result[:6])
	}

	if len(result) != 60 {
		t.Errorf("Error in GenerateHashedPassword: Resulting length should be 66 - got: %d", len(result))
	}
}

func TestGetAllIPAddresses(t *testing.T) {
	ifacesMap, err := GetAllIPAddresses()
	require.NoError(t, err)
	require.NotNil(t, ifacesMap)

	// If there are interfaces, each key should map to a non-empty IP string
	for iface, ip := range ifacesMap {
		require.NotEmpty(t, iface, "Interface name should not be empty")
		require.NotEmpty(t, ip, "IP address should not be empty")
	}
}
