package agent

import "testing"

func TestCredEnvName(t *testing.T) {
	for in, want := range map[string]string{
		"trungnd66@vingroup.net":       "TRUNGND66_VINGROUP_NET",
		"uat.vinsoc.sa-trungnd66-test": "UAT_VINSOC_SA_TRUNGND66_TEST",
	} {
		if got := credEnvName(in); got != want {
			t.Errorf("credEnvName(%q) = %q, want %q", in, got, want)
		}
	}
	if !jwtShape.MatchString("eyJhbGciOi.eyJzdWIiOjF9.c2ln-_x") || jwtShape.MatchString("not a jwt") {
		t.Error("jwtShape misclassifies")
	}
}
