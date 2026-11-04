package autostart

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const Label = "com.example.basicauthhelper"

type ErrUnsuitableLocation struct{ Path string }

func (e *ErrUnsuitableLocation) Error() string {
	return "请先把应用拖到「应用程序」文件夹再开启开机自启"
}
func ValidatePath(path string) error {
	if !filepath.IsAbs(path) || strings.Contains(path, "/AppTranslocation/") || strings.HasPrefix(path, "/Volumes/") || !strings.Contains(filepath.Clean(path), ".app/Contents/MacOS/") {
		return &ErrUnsuitableLocation{path}
	}
	return nil
}
func Plist(path string) ([]byte, error) {
	if err := ValidatePath(path); err != nil {
		return nil, err
	}
	var escaped bytes.Buffer
	if err := xml.EscapeText(&escaped, []byte(path)); err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>%s</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><false/>
<key>ProcessType</key><string>Interactive</string>
</dict></plist>
`, Label, escaped.String())), nil
}

// Agent accepts explicit paths for tests; New resolves the running executable's symlinks.
type Agent struct {
	Home, Executable string
	enabled          bool
}

func New() (*Agent, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return nil, err
	}
	return &Agent{Home: home, Executable: exe}, nil
}
func (a *Agent) Path() string {
	return filepath.Join(a.Home, "Library", "LaunchAgents", Label+".plist")
}
func (a *Agent) write() error {
	b, err := Plist(a.Executable)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(a.Path()), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(a.Path()), ".autostart-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0644); err == nil {
		_, err = f.Write(b)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), a.Path())
}

// PointsAt checks semantic plist values, independent of whitespace and key order.
func PointsAt(b []byte, executable string) bool {
	var doc struct {
		Dict struct {
			Inner string `xml:",innerxml"`
		} `xml:"dict"`
	}
	if xml.Unmarshal(b, &doc) != nil {
		return false
	}
	dec := xml.NewDecoder(strings.NewReader(doc.Dict.Inner))
	label, program := "", ""
	for {
		token, err := dec.Token()
		if err != nil {
			break
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "key" {
			continue
		}
		var key string
		if dec.DecodeElement(&key, &start) != nil {
			return false
		}
		for {
			token, err = dec.Token()
			if err != nil {
				return false
			}
			value, ok := token.(xml.StartElement)
			if !ok {
				continue
			}
			switch key {
			case "Label":
				if value.Name.Local != "string" || dec.DecodeElement(&label, &value) != nil {
					return false
				}
			case "ProgramArguments":
				var args struct {
					Strings []string `xml:"string"`
				}
				if value.Name.Local != "array" || dec.DecodeElement(&args, &value) != nil || len(args.Strings) != 1 {
					return false
				}
				program = args.Strings[0]
			default:
				if dec.Skip() != nil {
					return false
				}
			}
			break
		}
	}
	return label == Label && program == executable
}
