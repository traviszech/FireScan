package scanner

import (
	"testing"
	"time"
)

func TestAdaptiveTimingControllerAdjustsDelayOnFailures(t *testing.T) {
	controller := NewAdaptiveTimingController(1000)
	initial := controller.CurrentDelay()

	controller.Observe(ProbeOutcome{Success: false, RTT: 200 * time.Millisecond})
	adjusted := controller.CurrentDelay()

	if adjusted <= initial {
		t.Fatalf("expected delay to increase after failures, got %v -> %v", initial, adjusted)
	}
}

func TestAdaptiveTimingControllerRecoversOnSteadySuccess(t *testing.T) {
	controller := NewAdaptiveTimingController(1000)
	controller.Observe(ProbeOutcome{Success: false, RTT: 500 * time.Millisecond})
	controller.Observe(ProbeOutcome{Success: true, RTT: 20 * time.Millisecond})
	controller.Observe(ProbeOutcome{Success: true, RTT: 15 * time.Millisecond})
	controller.Observe(ProbeOutcome{Success: true, RTT: 10 * time.Millisecond})

	if controller.CurrentDelay() >= 100*time.Millisecond {
		t.Fatalf("expected delay to recover toward baseline, got %v", controller.CurrentDelay())
	}
}
