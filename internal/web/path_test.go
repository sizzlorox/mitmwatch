package web

import (
	"strings"
	"testing"
)

func TestPathDiagramIsSelfContained(t *testing.T) {
	p := PathView{Vantage: "Inside", Target: "example.com", Reached: true, Hops: []PathHop{
		{TTL: 1, Addr: "192.168.1.1", Class: "gateway"}, {TTL: 2}, {TTL: 3, Addr: "1.1.1.1", Class: "internet"},
	}}
	n := p.Nodes()
	if len(n) != 4 || n[2].Label != "?" || n[3].Label != "example.com" {
		t.Fatalf("unexpected nodes: %+v", n)
	}
	if p.Width() != p.Last()+hopMargin {
		t.Fatalf("width %d does not fit last node %d", p.Width(), p.Last())
	}
}

func TestPathSummaryIncludesHopClassesAndReachedStatus(t *testing.T) {
	p := PathView{Target: "example.com", Reached: false, Hops: []PathHop{
		{TTL: 1, Addr: "192.168.1.1", Class: "gateway"},
		{TTL: 2, Class: "unknown"},
		{TTL: 3, Addr: "10.0.0.1", Class: "local"},
	}}
	for _, want := range []string{
		"example.com", "not reached", "hop 1: gateway (192.168.1.1)",
		"hop 2: unknown (no reply)", "hop 3: local (10.0.0.1)",
	} {
		if !strings.Contains(p.Summary(), want) {
			t.Errorf("summary %q omits %q", p.Summary(), want)
		}
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
