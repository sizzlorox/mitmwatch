package web

import (
	"strings"
	"testing"
)

func TestPathDiagramIsSelfContained(t *testing.T) {
	p := PathView{Vantage: "Inside", Target: "1.1.1.1", Reached: true, Hops: []PathHop{
		{TTL: 1, Addr: "192.168.1.1", Class: "gateway"}, {TTL: 2},
	}}
	n := p.Nodes()
	if len(n) != 4 || n[2].Label != "?" || n[3].Label != "1.1.1.1" {
		t.Fatalf("unexpected nodes: %+v", n)
	}
	if p.Width() != p.Last()+hopMargin {
		t.Fatalf("width %d does not fit last node %d", p.Width(), p.Last())
	}
}

func TestPathTemplateHasNoExternalReferences(t *testing.T) {
	b, err := files.ReadFile("templates/path.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"http://", "https://", "src="} {
		if strings.Contains(string(b), bad) {
			t.Fatalf("path page references %q", bad)
		}
	}
}
