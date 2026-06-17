package nuclei

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/Method-Security/networkscan/generated/go/common"
	"gopkg.in/yaml.v3"
)

func TestEmbeddedTemplatesDeclareKnownProtocols(t *testing.T) {
	var checked int

	err := fs.WalkDir(All, "cve", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isTemplateFile(path) {
			return nil
		}

		checked++
		data, readErr := fs.ReadFile(All, path)
		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}

		var template struct {
			Info struct {
				Metadata map[string]any `yaml:"metadata"`
			} `yaml:"info"`
		}
		if unmarshalErr := yaml.Unmarshal(data, &template); unmarshalErr != nil {
			t.Fatalf("parse %s: %v", path, unmarshalErr)
		}

		raw, ok := template.Info.Metadata["protocol"]
		if !ok {
			t.Errorf("%s: missing info.metadata.protocol", path)
			return nil
		}
		protocol, ok := raw.(string)
		if !ok {
			t.Errorf("%s: info.metadata.protocol must be a string, got %T", path, raw)
			return nil
		}

		normalized := strings.ToUpper(strings.TrimSpace(protocol))
		switch normalized {
		case "", "UNKNOWN", "UNKNWON":
			t.Errorf("%s: invalid info.metadata.protocol %q", path, protocol)
			return nil
		}
		if _, parseErr := common.NewProtocolTypeFromString(normalized); parseErr != nil {
			t.Errorf("%s: unsupported info.metadata.protocol %q", path, protocol)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded templates: %v", err)
	}
	if checked == 0 {
		t.Fatal("no embedded templates checked")
	}
}
