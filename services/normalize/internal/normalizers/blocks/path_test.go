package blocks_test

import (
	"context"
	"errors"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers/blocks"
	"vulnmanager/services/normalize/internal/normalizers/normtest"
)

func testPathRules(t *testing.T) blocks.PathRules {
	t.Helper()
	rules, err := blocks.NewPathRules([]string{"/src/", "/home/runner/work/*/*/", "/app/"})
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	return rules
}

func pathFinding(location string) model.Finding {
	return model.Finding{ToolFindingID: model.ToolFindingID(location), Location: []byte(location)}
}

func TestPath_Normalize(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"build prefix", `{"uri":"/src/pkg/a.go","start_line":3}`, `{"start_line":3,"uri":"pkg/a.go"}`},
		{"wildcard prefix", `{"uri":"/home/runner/work/repo/repo/pkg/a.go"}`, `{"uri":"pkg/a.go"}`},
		{"backslashes", `{"uri":"pkg\\sub\\a.go"}`, `{"uri":"pkg/sub/a.go"}`},
		{"dot segments", `{"uri":"./pkg/../lib//a.go"}`, `{"uri":"lib/a.go"}`},
		{"unknown absolute stays absolute", `{"uri":"/opt/x/a.go"}`, `{"uri":"/opt/x/a.go"}`},
		{"prefix alone is not stripped", `{"uri":"/src/"}`, `{"uri":"/src"}`},
		{"other fields untouched", `{"package":"\\a\\b","target":"/app/package-lock.json"}`, `{"package":"\\a\\b","target":"package-lock.json"}`},
		{"already clean", `{"uri":"pkg/a.go"}`, `{"uri":"pkg/a.go"}`},
		{"empty value", `{"target":""}`, `{"target":""}`},
		{"not an object", `["/src/a.go"]`, `["/src/a.go"]`},
		{"not a string", `{"uri":42}`, `{"uri":42}`},
		{"empty", ``, ``},
	}
	n := blocks.NewPath(testPathRules(t), "uri", "target")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pathFinding(c.in)
			if err := n.Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if string(got.Location) != c.want {
				t.Fatalf("got %s, want %s", got.Location, c.want)
			}
		})
	}
}

func TestPath_Suite(t *testing.T) {
	normtest.Suite(t, blocks.NewPath(testPathRules(t), "uri", "target"), []model.Finding{
		pathFinding(`{"uri":"/home/runner/work/repo/repo/pkg/a.go","start_line":3}`),
		pathFinding(`{"uri":"pkg\\a.go"}`),
		pathFinding(`{"target":"/app/app/package-lock.json"}`),
		pathFinding(`{"uri":"/src/src/a.go"}`),
		pathFinding(``),
	})
}

func TestNewPathRules_RejectsBadPrefixes(t *testing.T) {
	for _, prefix := range []string{"src/", "/src", "/", "/a//b/", ""} {
		t.Run(prefix, func(t *testing.T) {
			if _, err := blocks.NewPathRules([]string{prefix}); !errors.Is(err, blocks.ErrInvalidPathRules) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestStandardPathRules(t *testing.T) {
	rules, err := blocks.StandardPathRules()
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	got := pathFinding(`{"uri":"/home/runner/work/repo/repo/pkg/a.go"}`)
	if err := blocks.NewPath(rules, "uri").Normalize(context.Background(), &got); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if string(got.Location) != `{"uri":"pkg/a.go"}` {
		t.Fatalf("got %s", got.Location)
	}
}
