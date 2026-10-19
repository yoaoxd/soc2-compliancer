package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Component struct {
	Provider      string   `json:"provider"`
	Name          string   `json:"name"`
	Path          string   `json:"-"`
	ResourceTypes []string `json:"resource_types"`
	Description   string   `json:"description"`
	Version       string   `json:"version"`
	Category      string   `json:"category"`
	Controls      []string `json:"controls"`
	Dependencies  []string `json:"dependencies,omitempty"`
	Tests         []string `json:"tests,omitempty"`
	Variables     []Var    `json:"variables,omitempty"`
	Wiring        []Wiring `json:"wiring,omitempty"`
}

type Var struct {
	Name     string `json:"name" yaml:"name"`
	Type     string `json:"type,omitempty" yaml:"type,omitempty"`
	Required bool   `json:"required" yaml:"required"`
	Default  string `json:"default,omitempty" yaml:"default,omitempty"`
}

// Wiring connects a module variable to an output of another included module,
// e.g. a CMEK key id flowing into a dependent resource.
type Wiring struct {
	Variable string `json:"variable" yaml:"variable"`
	Module   string `json:"module" yaml:"module"`
	Output   string `json:"output" yaml:"output"`
}

type Provider struct {
	Name        string      `json:"name"`
	DisplayName string      `json:"display_name"`
	Components  []Component `json:"components"`
}

var knownProviders = map[string]string{
	"gcp":   "Google Cloud Platform",
	"aws":   "Amazon Web Services",
	"azure": "Microsoft Azure",
}

// Load scans <root>/<provider>/<component>/metadata.yaml for every provider.
func Load(root string) ([]Provider, error) {
	dirs, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read templates dir: %w", err)
	}

	var providers []Provider
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		provider := d.Name()
		display, ok := knownProviders[provider]
		if !ok {
			continue
		}
		comps, err := loadComponents(filepath.Join(root, provider))
		if err != nil {
			return nil, err
		}
		providers = append(providers, Provider{Name: provider, DisplayName: display, Components: comps})
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Name < providers[j].Name })
	return providers, nil
}

func loadComponents(providerDir string) ([]Component, error) {
	dirs, err := os.ReadDir(providerDir)
	if err != nil {
		return nil, fmt.Errorf("read provider dir %s: %w", providerDir, err)
	}
	var out []Component
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		metaPath := filepath.Join(providerDir, d.Name(), "metadata.yaml")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		var raw struct {
			Name          string   `yaml:"name"`
			ResourceTypes []string `yaml:"resource_types"`
			Description   string   `yaml:"description"`
			Version       string   `yaml:"version"`
			Category      string   `yaml:"category"`
			Controls      []string `yaml:"controls"`
			Dependencies  []string `yaml:"dependencies"`
			Tests         []string `yaml:"tests"`
			Variables     []Var    `yaml:"variables"`
			Wiring        []Wiring `yaml:"wiring"`
		}
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("parse %s: %w", metaPath, err)
		}
		name := raw.Name
		if name == "" {
			name = d.Name()
		}
		provider := filepath.Base(providerDir)
		out = append(out, Component{
			Provider:      provider,
			Name:          name,
			Path:          filepath.Join(providerDir, d.Name()),
			ResourceTypes: raw.ResourceTypes,
			Description:   raw.Description,
			Version:       raw.Version,
			Category:      raw.Category,
			Controls:      raw.Controls,
			Dependencies:  raw.Dependencies,
			Tests:         raw.Tests,
			Variables:     raw.Variables,
			Wiring:        raw.Wiring,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Filter applies query params (category, resource_type).
func Filter(providers []Provider, category, resourceType string) []Provider {
	if category == "" && resourceType == "" {
		return providers
	}
	var out []Provider
	for _, p := range providers {
		comps := make([]Component, 0, len(p.Components))
		for _, c := range p.Components {
			if category != "" && c.Category != category {
				continue
			}
			if resourceType != "" && !contains(c.ResourceTypes, resourceType) {
				continue
			}
			comps = append(comps, c)
		}
		if len(comps) > 0 {
			p.Components = comps
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
