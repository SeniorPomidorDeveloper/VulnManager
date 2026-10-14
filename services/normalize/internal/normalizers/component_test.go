package normalizers_test

import (
	"context"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/normalizers/normtest"
)

func componentFinding(raw model.PURLRaw) model.Finding {
	return model.Finding{ToolFindingID: model.ToolFindingID("id/" + string(raw)), PURLRaw: raw}
}

func TestComponent_Normalize(t *testing.T) {
	cases := []struct {
		name string
		raw  model.PURLRaw
		want model.Component
	}{
		{
			"scoped npm", "pkg:npm/%40TooTallNate/Once@1.1.2",
			model.Component{PURL: "pkg:npm/%40tootallnate/once@1.1.2", Type: "npm", Namespace: "@tootallnate", Name: "once", Version: "1.1.2"},
		},
		{
			"pypi name", "pkg:pypi/Django_Rest_Framework@3.14.0",
			model.Component{PURL: "pkg:pypi/django-rest-framework@3.14.0", Type: "pypi", Name: "django-rest-framework", Version: "3.14.0"},
		},
		{
			"golang lowercased", "pkg:golang/GitHub.com/Foo/Bar@v1.2.3",
			model.Component{PURL: "pkg:golang/github.com/foo/bar@v1.2.3", Type: "golang", Namespace: "github.com/foo", Name: "bar", Version: "v1.2.3"},
		},
		{
			"maven keeps case", "pkg:maven/org.Apache/Commons-Lang3@3.12.0",
			model.Component{PURL: "pkg:maven/org.Apache/Commons-Lang3@3.12.0", Type: "maven", Namespace: "org.Apache", Name: "Commons-Lang3", Version: "3.12.0"},
		},
		{
			"deb qualifiers sorted, subpath dropped", "PKG:DEB/Debian/Curl@7.88.1-10%2Bdeb12u5?distro=debian-12&arch=amd64#bin",
			model.Component{PURL: "pkg:deb/debian/curl@7.88.1-10%2Bdeb12u5?arch=amd64&distro=debian-12", Type: "deb", Namespace: "debian", Name: "curl", Version: "7.88.1-10+deb12u5"},
		},
		{
			"no version", "pkg:npm/lodash",
			model.Component{PURL: "pkg:npm/lodash", Type: "npm", Name: "lodash"},
		},
		{
			"extra slashes after scheme", "pkg://npm/lodash@4.17.21",
			model.Component{PURL: "pkg:npm/lodash@4.17.21", Type: "npm", Name: "lodash", Version: "4.17.21"},
		},
		{"empty", "  ", model.Component{}},
	}
	n := normalizers.NewComponent()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := componentFinding(c.raw)
			if err := n.Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if got.Component != c.want {
				t.Fatalf("got %+v, want %+v", got.Component, c.want)
			}
			if len(got.Diagnostics) != 0 {
				t.Fatalf("diagnostics %+v", got.Diagnostics)
			}
		})
	}
}

func TestComponent_InvalidPURLDegradesWithDiagnostic(t *testing.T) {
	for _, raw := range []model.PURLRaw{"npm/lodash@1", "pkg:npm", "pkg:npm//lodash", "pkg:npm/lo%zzdash@1", "pkg:npm/lodash@1?bad"} {
		t.Run(string(raw), func(t *testing.T) {
			got := componentFinding(raw)
			if err := normalizers.NewComponent().Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if !got.Component.IsZero() || !got.Diagnostics.Has("invalid_purl") {
				t.Fatalf("component %+v diagnostics %+v", got.Component, got.Diagnostics)
			}
		})
	}
}

func TestComponent_Suite(t *testing.T) {
	normtest.Suite(t, normalizers.NewComponent(), []model.Finding{
		componentFinding("pkg:npm/%40Scope/Pkg@1.0.0"),
		componentFinding("pkg:deb/debian/curl@7.88.1?distro=debian-12&arch=amd64"),
		componentFinding("garbage"),
		componentFinding(""),
	})
}
