//go:build linux

package controlapi

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/control"
)

func TestDaeProviderTrafficUsesControlPlaneCounters(t *testing.T) {
	plane := &control.ControlPlane{}
	provider := &DaeProvider{plane: plane}

	first := provider.Traffic()
	if first.Up != 0 || first.Down != 0 || first.UpTotal != 0 || first.DownTotal != 0 {
		t.Fatalf("initial traffic = %+v, want zero snapshot", first)
	}

	plane.AddUploadTraffic(2048)
	plane.AddDownloadTraffic(4096)
	time.Sleep(25 * time.Millisecond)

	second := provider.Traffic()
	if second.UpTotal != 2048 {
		t.Fatalf("second UpTotal = %d, want 2048", second.UpTotal)
	}
	if second.DownTotal != 4096 {
		t.Fatalf("second DownTotal = %d, want 4096", second.DownTotal)
	}
	if second.Up <= 0 {
		t.Fatalf("second Up = %d, want positive rate", second.Up)
	}
	if second.Down <= 0 {
		t.Fatalf("second Down = %d, want positive rate", second.Down)
	}

	time.Sleep(20 * time.Millisecond)
	third := provider.Traffic()
	if third.UpTotal != second.UpTotal || third.DownTotal != second.DownTotal {
		t.Fatalf("third totals changed without new traffic: %+v", third)
	}
	if third.Up != 0 || third.Down != 0 {
		t.Fatalf("third rates = %+v, want zero without new bytes", third)
	}
}
