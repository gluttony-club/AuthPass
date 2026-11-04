package autostart

import (
	"encoding/xml"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPlistAndLocations(t *testing.T) {
	for _, path := range []string{"/Volumes/Disk/A.app/Contents/MacOS/helper", "/private/AppTranslocation/id/A.app/Contents/MacOS/helper", "/usr/local/bin/helper", "A.app/Contents/MacOS/helper"} {
		var target *ErrUnsuitableLocation
		if !errors.As(ValidatePath(path), &target) {
			t.Fatalf("accepted %s", path)
		}
	}
	path := "/Applications/A & B.app/Contents/MacOS/helper"
	b, err := Plist(path)
	if err != nil {
		t.Fatal(err)
	}
	if !PointsAt(b, path) || PointsAt(b, path+"old") {
		t.Fatal("plist path detection")
	}
	var doc any
	if err := xml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{Label, "A &amp; B.app", "<key>RunAtLoad</key><true/>", "<key>KeepAlive</key><false/>", "<string>Interactive</string>"} {
		if !strings.Contains(string(b), text) {
			t.Fatal(string(b))
		}
	}
	a := &Agent{Home: t.TempDir(), Executable: path}
	if err := a.write(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(a.Path())
	if err != nil || st.Mode().Perm() != 0644 {
		t.Fatal(st, err)
	}
	a.Executable = "/usr/bin/helper"
	if err := a.write(); err == nil {
		t.Fatal("unsuitable path accepted")
	}
	after, _ := os.ReadFile(a.Path())
	if string(after) != string(b) {
		t.Fatal("changed on failure")
	}
}
