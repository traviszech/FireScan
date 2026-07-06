package main

import "testing"

func TestRootCommandRegistersShortcutFlags(t *testing.T) {
	cmd := newRootCommand()

	required := []string{"top100", "top1000", "max-hosts", "dry-run", "no-failover"}
	for _, name := range required {
		if cmd.Flags().Lookup(name) == nil {
			t.Fatalf("expected flag %q to be registered", name)
		}
	}
}
