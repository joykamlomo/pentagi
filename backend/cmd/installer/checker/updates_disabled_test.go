package checker

import (
	"context"
	"sync"
	"testing"
)

// With no UPDATE_SERVER_URL configured the installer must not contact any
// update server: it reports "not accessible" and leaves update flags untouched.
func TestGatherUpdatesInfo_DisabledByDefault(t *testing.T) {
	h := &defaultCheckHandler{mx: &sync.Mutex{}}
	c := &CheckResult{}

	if err := h.GatherUpdatesInfo(context.Background(), c); err != nil {
		t.Fatalf("GatherUpdatesInfo() error = %v", err)
	}
	if c.UpdateServerAccessible {
		t.Error("UpdateServerAccessible = true, want false when no update server is configured")
	}
}
