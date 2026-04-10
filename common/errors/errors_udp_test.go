package errors

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestIsUDPEndpointNormalClose_ConnectionRefused(t *testing.T) {
	err := &net.OpError{
		Op:  "read",
		Net: "udp",
		Err: &os.SyscallError{
			Syscall: "read",
			Err:     syscall.ECONNREFUSED,
		},
	}

	if IsUDPEndpointNormalClose(err) {
		t.Fatalf("expected ECONNREFUSED to be treated as a real UDP endpoint failure, got normal close")
	}
}

func TestIsUDPEndpointNormalClose_Patterns(t *testing.T) {
	patterns := []string{
		"websocket: close 1000 (normal)",
		"websocket: close 1001 (going away)",
		"websocket: close 1005 (no status)",
		"client closed",
		"too many open streams",
		"Application error 0x100 (NoError)",
		"quic: NO_ERROR",
		"stream reset",
		"connection timed out",
	}

	for _, p := range patterns {
		err := net.UnknownNetworkError(p)
		if !IsUDPEndpointNormalClose(err) {
			t.Errorf("expected pattern %q to be treated as normal close", p)
		}
	}
}
