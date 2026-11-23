package utils

import (
	"context"
	"testing"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/stretchr/testify/require"
)

// discoverable browses service for up to 3s and reports whether an instance
// with the given name and port answered.
func discoverable(t *testing.T, service, instance string, port int) bool {
	t.Helper()
	resolver, err := zeroconf.NewResolver(nil)
	require.NoError(t, err)
	entries := make(chan *zeroconf.ServiceEntry)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, resolver.Browse(ctx, service, "local.", entries))
	for {
		select {
		case e := <-entries:
			if e != nil && e.Port == port && e.Instance == instance {
				return true
			}
		case <-ctx.Done():
			return false
		}
	}
}

// The advertised services must still be discoverable after RegisterZeroconfMDNS
// returns. Each registration used to be deferred-shutdown inside the function,
// so every service was withdrawn immediately and nothing could ever be found.
func TestRegisterZeroconfMDNS_StaysRegistered(t *testing.T) {
	// Calibrate: some sandboxes/VMs do not loop multicast back to the host, so
	// a process cannot discover even its own registration. Skip there.
	control, err := zeroconf.Register("goshs control", "_goshs-test._udp", "local.", 47071, []string{"x=y"}, nil)
	if err != nil {
		t.Skipf("mDNS not available in this environment: %v", err)
	}
	ok := discoverable(t, "_goshs-test._udp", "goshs control", 47071)
	control.Shutdown()
	if !ok {
		t.Skip("multicast loopback unavailable: cannot discover a local mDNS registration")
	}

	const port = 47069
	shutdown, err := RegisterZeroconfMDNS(true, false, 47080, false, 0, false, 0, false, 0, false, 0, false, 0, false, false, 0, true, port)
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	defer shutdown()

	require.True(t, discoverable(t, "_tftp._udp", "goshs TFTP", port),
		"service must still be advertised after registration returns")
}
