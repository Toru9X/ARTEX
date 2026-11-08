package server

import "testing"

func TestAutoTitleMayReplace(t *testing.T) {
	for _, current := range []string{"", "New conversation", "first message preview"} {
		if !autoTitleMayReplace(current, "first message preview") {
			t.Fatalf("expected %q to be replaceable", current)
		}
	}
	if autoTitleMayReplace("a title the user set by hand", "first message preview") {
		t.Fatal("manual title must not be overwritten")
	}
}

func TestAutoTitleIsUsable(t *testing.T) {
	for _, generated := range []string{"", "New conversation"} {
		if autoTitleIsUsable(generated) {
			t.Fatalf("placeholder title %q must be rejected", generated)
		}
	}
	if !autoTitleIsUsable("tidy up the project settings") {
		t.Fatal("generated title should be accepted")
	}
}
