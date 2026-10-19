package tests

import (
	"testing"

	"github.com/soc2-compliancer/app/internal/catalog"
)

func TestCatalogLoad(t *testing.T) {
	providers, err := catalog.Load("testdata/templates")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("want 1 provider (gcp), got %d", len(providers))
	}
	if providers[0].Name != "gcp" {
		t.Fatalf("want gcp provider, got %s", providers[0].Name)
	}
	if len(providers[0].Components) != 1 {
		t.Fatalf("want 1 component, got %d", len(providers[0].Components))
	}
	comp := providers[0].Components[0]
	if comp.Name != "storage_bucket" {
		t.Fatalf("want storage_bucket, got %s", comp.Name)
	}
	if len(comp.Controls) != 5 {
		t.Fatalf("want 5 mapped controls, got %d", len(comp.Controls))
	}
}

func TestCatalogFilter(t *testing.T) {
	providers, _ := catalog.Load("testdata/templates")
	filtered := catalog.Filter(providers, "storage", "")
	if len(filtered) != 1 {
		t.Fatal("expected storage category to match")
	}
	filtered = catalog.Filter(providers, "compute", "")
	if len(filtered) != 0 {
		t.Fatal("expected no compute components")
	}
}
