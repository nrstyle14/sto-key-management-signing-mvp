package version

import "testing"

func TestString(t *testing.T) {
	Version, Commit = "v0.0.0-test", "abc123"
	got := String("signerd")
	want := "signerd v0.0.0-test (abc123)"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
