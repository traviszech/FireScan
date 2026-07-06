package scanner

import "time"

// ProbeOutcome captures a single scan attempt result for adaptive pacing.
type ProbeOutcome struct {
	Success bool
	RTT     time.Duration
}

// AdaptiveTimingController adjusts inter-probe delay dynamically in response to failures and latency.
type AdaptiveTimingController struct {
	baseDelay    time.Duration
	currentDelay time.Duration
	minDelay     time.Duration
	maxDelay     time.Duration
}

// NewAdaptiveTimingController creates a deterministic pacing controller.
func NewAdaptiveTimingController(baseDelayMicros int) *AdaptiveTimingController {
	if baseDelayMicros <= 0 {
		baseDelayMicros = 1000
	}

	baseDelay := time.Duration(baseDelayMicros) * time.Microsecond
	return &AdaptiveTimingController{
		baseDelay:    baseDelay,
		currentDelay: baseDelay,
		minDelay:     time.Microsecond,
		maxDelay:     250 * time.Millisecond,
	}
}

// Observe updates the delay based on the most recent probe result.
func (c *AdaptiveTimingController) Observe(outcome ProbeOutcome) {
	if c == nil {
		return
	}

	if outcome.Success {
		c.currentDelay = maxDuration(c.baseDelay, c.currentDelay/2)
		if c.currentDelay < c.baseDelay {
			c.currentDelay = c.baseDelay
		}
		return
	}

	c.currentDelay = minDuration(c.currentDelay*2, c.maxDelay)
	if c.currentDelay < c.baseDelay {
		c.currentDelay = c.baseDelay
	}
}

// CurrentDelay returns the currently configured delay.
func (c *AdaptiveTimingController) CurrentDelay() time.Duration {
	if c == nil {
		return 0
	}
	return c.currentDelay
}

// Wait sleeps according to the current pacing configuration.
func (c *AdaptiveTimingController) Wait() {
	if c == nil || c.currentDelay <= 0 {
		return
	}
	time.Sleep(c.currentDelay)
}

func maxDuration(values ...time.Duration) time.Duration {
	result := time.Duration(0)
	for _, value := range values {
		if value > result {
			result = value
		}
	}
	return result
}

func minDuration(values ...time.Duration) time.Duration {
	result := time.Duration(1<<63 - 1)
	for _, value := range values {
		if value < result {
			result = value
		}
	}
	return result
}
