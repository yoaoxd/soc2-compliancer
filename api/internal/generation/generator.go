package generation

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/soc2-compliancer/app/internal/catalog"
)

var providerNameToTF = map[string]struct {
	providerName string
	providerSrc  string
	version      string
}{
	"gcp":   {providerName: "google", providerSrc: "hashicorp/google", version: "~> 6.0"},
	"aws":   {providerName: "aws", providerSrc: "hashicorp/aws", version: "~> 5.0"},
	"azure": {providerName: "azurerm", providerSrc: "hashicorp/azurerm", version: "~> 3.0"},
}

type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type Request struct {
	// Provider is the default provider for components that do not declare one.
	Provider string `json:"provider"`
	// Providers is the full set of providers included in this single bundle.
	// It is only required when components come from more than one provider.
	Providers  []string         `json:"providers,omitempty"`
	Components []ComponentInput `json:"components"`
}

type ComponentInput struct {
	// Provider overrides the request-level Provider for this component.
	Provider  string            `json:"provider,omitempty"`
	Name      string            `json:"name"`
	Variables map[string]string `json:"variables,omitempty"`
}

type Result struct {
	Provider   string   `json:"provider"` // comma-joined when multi-provider
	Providers  []string `json:"providers,omitempty"`
	Components []string `json:"components"`
	Controls   []string `json:"controls"`
	Warnings   []string `json:"warnings,omitempty"`
	Files      []File   `json:"files"`
}

type Service struct {
	templatesDir string
}

// pkg groups a single provider's resolved dependency subgraph within a bundle.
type pkg struct {
	resolved map[string]resolvedComponent
	order    []string
	warnings []string
}

func NewService(templatesDir string) *Service {
	return &Service{templatesDir: templatesDir}
}

// Generate composes a self-contained Terraform bundle from the selected
// components. Components may span multiple providers; they are all folded into
// a single bundle. Dependencies declared in metadata.yaml are auto-included and
// module sources are vendored under modules/<provider>/<name>.
func (s *Service) Generate(_ context.Context, req Request) (*Result, error) {
	all, err := catalog.Load(s.templatesDir)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	byProvider := make(map[string]map[string]catalog.Component, len(all))
	providerOrder := []string{}
	for i := range all {
		byName := map[string]catalog.Component{}
		for _, c := range all[i].Components {
			byName[c.Name] = c
		}
		byProvider[all[i].Name] = byName
		providerOrder = append(providerOrder, all[i].Name)
	}

	// Assign each requested component to a provider (explicit > default).
	type assigned struct {
		provider  string
		component catalog.Component
		variables map[string]string
		explicit  bool
	}
	var assignedComp []assigned
	used := map[string]bool{}
	for _, cr := range req.Components {
		prov := cr.Provider
		if prov == "" {
			prov = req.Provider
		}
		if prov == "" {
			if len(req.Providers) == 1 {
				prov = req.Providers[0]
			} else {
				return nil, fmt.Errorf("component %q needs a provider", cr.Name)
			}
		}
		if _, tf := providerNameToTF[prov]; !tf {
			return nil, fmt.Errorf("unsupported provider %q", prov)
		}
		byName, ok := byProvider[prov]
		if !ok {
			return nil, fmt.Errorf("provider %q not found in catalog", prov)
		}
		comp, ok := byName[cr.Name]
		if !ok {
			return nil, fmt.Errorf("component %q not found for provider %q", cr.Name, prov)
		}
		assignedComp = append(assignedComp, assigned{
			provider: prov, component: comp, variables: cr.Variables, explicit: true,
		})
		used[prov] = true
	}

	if len(assignedComp) == 0 {
		return nil, fmt.Errorf("no components selected")
	}

	// Settings providers: explicit list wins, otherwise derived.
	providers := sortedKeys(used, providerOrder, req.Providers)
	multi := len(providers) > 1

	// Resolve each provider's subgraph (dependencies stay within a provider).
	pkgs := map[string]*pkg{}
	var finalOrder []string
	for _, prov := range providers {
		byName := byProvider[prov]
		var inputs []ComponentInput
		for _, a := range assignedComp {
			if a.provider == prov {
				inputs = append(inputs, ComponentInput{
					Name: a.component.Name, Variables: a.variables,
				})
			}
		}
		if len(inputs) == 0 {
			// Provider listed but no components requested for it.
			inputs = nil
		}
		resolved, order, warnings, err := resolve(byName, inputs)
		if err != nil {
			return nil, err
		}
		pkgs[prov] = &pkg{resolved: resolved, order: order, warnings: warnings}
		// Modules are vendored under a per-provider dir, so module identities
		// are keyed with the provider to avoid name collisions in TF blocks
		// (e.g. gcp/kms_key vs aws/kms_key both exist).
		finalOrder = append(finalOrder, order...)
	}

	var warnings []string
	var files []File
	files = append(files, File{"versions.tf", buildVersions(providers)})
	files = append(files, File{"variables.tf", buildVariables(multi, providers, pkgs)})
	files = append(files, File{"main.tf", buildMain(multi, providers, pkgs)})
	files = append(files, File{"outputs.tf", buildOutputs(multi, providers, pkgs)})
	files = append(files, File{"README.md", buildReadme(multi, providers, pkgs, warnings)})
	files = append(files, File{"tests/run-checks.sh", testRunnerScript})
	warnings = append(warnings, collectWarnings(pkgs, providers)...)

	// Vendor each module's source.
	for _, prov := range providers {
		p := pkgs[prov]
		for _, name := range p.order {
			cmp := p.resolved[name].component
			for _, f := range moduleFiles(cmp.Path) {
				path := "modules/" + prov + "/" + cmp.Name + "/" + f.Path
				files = append(files, File{path, f.Content})
			}
		}
	}

	controls := coveredControls(providers, pkgs)
	return &Result{
		Provider:   strings.Join(providers, ","),
		Providers:  providers,
		Components: finalOrderAs(finalOrder),
		Controls:   controls,
		Warnings:   warnings,
		Files:      files,
	}, nil
}

// Zip renders the bundle as a .zip archive (does not need the DB).
func (r *Result) Zip() ([]byte, error) {
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	for _, f := range r.Files {
		w, err := zw.Create(f.Path)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(f.Content)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type resolvedComponent struct {
	provider  string
	component catalog.Component
	explicit  bool
	variables map[string]string // module var -> value (user-provided)
}

func resolve(byName map[string]catalog.Component, inputs []ComponentInput) (map[string]resolvedComponent, []string, []string, error) {
	resolved := map[string]resolvedComponent{}
	var order []string
	var warnings []string

	userVars := map[string]map[string]string{}
	for _, cr := range inputs {
		userVars[cr.Name] = cr.Variables
	}

	var visit func(name string, explicit bool) error
	var visitDeps func(v func(string, bool) error, comp catalog.Component) error

	visit = func(name string, explicit bool) error {
		if _, done := resolved[name]; done {
			return nil
		}
		comp, ok := byName[name]
		if !ok {
			return fmt.Errorf("component %q not found for provider", name)
		}
		if err := visitDeps(visit, comp); err != nil {
			return err
		}
		vars := map[string]string{}
		if v, ok := userVars[name]; ok {
			for k, val := range v {
				vars[k] = val
			}
		}
		resolved[name] = resolvedComponent{provider: comp.Provider, component: comp, explicit: explicit, variables: vars}
		order = append(order, name)
		return nil
	}

	visitDeps = func(v func(string, bool) error, comp catalog.Component) error {
		for _, dep := range comp.Dependencies {
			if _, ok := byName[dep]; !ok {
				warnings = append(warnings, fmt.Sprintf("dependency %q of %q is not available in the catalog", dep, comp.Name))
				continue
			}
			if _, already := resolved[dep]; !already {
				warnings = append(warnings, fmt.Sprintf("auto-included required dependency %q for %q", dep, comp.Name))
			}
			if err := v(dep, false); err != nil {
				return err
			}
		}
		return nil
	}

	for _, cr := range inputs {
		if err := visit(cr.Name, true); err != nil {
			return nil, nil, nil, err
		}
	}
	return resolved, order, warnings, nil
}

func coveredControls(providers []string, pkgs map[string]*pkg) []string {
	set := map[string]bool{}
	for _, prov := range providers {
		p := pkgs[prov]
		for _, n := range p.order {
			for _, c := range p.resolved[n].component.Controls {
				set[c] = true
			}
		}
	}
	controls := make([]string, 0, len(set))
	for c := range set {
		controls = append(controls, c)
	}
	sort.Strings(controls)
	return controls
}

func moduleFiles(dir string) []File {
	var out []File
	for _, name := range []string{"main.tf", "variables.tf", "outputs.tf", "README.md", "metadata.yaml"} {
		path := dir + "/" + name
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		out = append(out, File{Path: name, Content: string(b)})
	}
	return out
}

func sortedNames(resolved map[string]resolvedComponent) []string {
	names := make([]string, 0, len(resolved))
	for n := range resolved {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// literalDefault renders a default literal based on the Terraform type.
func literalDefault(typ, have, metaDefault string) string {
	v := have
	if v == "" {
		v = metaDefault
	}
	switch typ {
	case "number", "bool":
		if v == "" || v == "true" || v == "false" {
			if v == "" {
				return "null"
			}
			return v
		}
		return v
	case "list(map(string))", "list(string)", "map(string)":
		if v == "" {
			return "null"
		}
		return v
	default:
		if v == "" {
			return "null"
		}
		return fmt.Sprintf("%q", v)
	}
}

func buildVersions(providers []string) string {
	var b strings.Builder
	b.WriteString("terraform {\n  required_providers {\n")
	for _, prov := range providers {
		tf := providerNameToTF[prov]
		fmt.Fprintf(&b, "    %s = {\n      source  = %q\n      version = %q\n    }\n",
			tf.providerName, tf.providerSrc, tf.version)
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

func buildVariables(multi bool, providers []string, pkgs map[string]*pkg) string {
	var b strings.Builder
	b.WriteString("# Fill in these inputs before applying. Required inputs are marked below.\n")
	for _, prov := range providers {
		p := pkgs[prov]
		names := sortedNames(p.resolved)
		for _, n := range names {
			rc := p.resolved[n]
			for _, v := range rc.component.Variables {
				have := rc.variables[v.Name]
				desc := v.Default
				if desc == "" {
					desc = v.Name
				}
				typ := v.Type
				if typ == "" {
					typ = "string"
				}
				lit := literalDefault(typ, have, v.Default)
				req := ""
				if v.Required {
					req = " (required)"
				}
				fmt.Fprintf(&b, "variable %q {\n  description = %q\n  type        = %s\n  default     = %s\n}\n\n",
					variableName(multi, prov, n, v.Name), desc+req, typ, lit)
			}
		}
	}
	return b.String()
}

func buildMain(multi bool, providers []string, pkgs map[string]*pkg) string {
	var b strings.Builder
	b.WriteString("# Generated by SOC2 Compliancer — do not edit by hand.\n")
	for _, prov := range providers {
		p := pkgs[prov]
		for _, n := range p.order {
			rc := p.resolved[n]
			fmt.Fprintf(&b, "module %q {\n  source = %q\n", moduleName(multi, prov, n), "./modules/"+prov+"/"+n)
			for _, v := range rc.component.Variables {
				fmt.Fprintf(&b, "  %-24s = %s\n", v.Name, inputExpr(multi, prov, pkgs, n, v.Name))
			}
			b.WriteString("}\n\n")
		}
	}
	return b.String()
}

func buildOutputs(multi bool, providers []string, pkgs map[string]*pkg) string {
	var b strings.Builder
	b.WriteString("# Notable outputs from the selected modules.\n")
	for _, prov := range providers {
		p := pkgs[prov]
		for _, n := range p.order {
			outs := extractOutputs(p.resolved[n].component.Path)
			for _, o := range outs {
				fmt.Fprintf(&b, "output %q {\n  value = module.%s.%s\n}\n\n",
					outputName(multi, prov, n, o), moduleName(multi, prov, n), o)
			}
		}
	}
	return b.String()
}

func buildReadme(multi bool, providers []string, pkgs map[string]*pkg, warnings []string) string {
	var b strings.Builder
	b.WriteString("# Terraform bundle — SOC2 Compliancer\n\n")
	b.WriteString("Providers: **" + strings.Join(providers, ", ") + "**\n\n")
	b.WriteString("This bundle provisions the following components (dependencies auto-included):\n\n")
	for _, prov := range providers {
		p := pkgs[prov]
		for _, n := range p.order {
			rc := p.resolved[n]
			mark := ""
			if !rc.explicit {
				mark = " (dependency)"
			}
			fmt.Fprintf(&b, "- `%s`%s (%s) — %s\n", n, mark, prov, rc.component.Description)
		}
	}
	b.WriteString("\n## SOC2 controls covered\n")
	for _, c := range coveredControls(providers, pkgs) {
		fmt.Fprintf(&b, "- %s\n", c)
	}
	if len(warnings) > 0 {
		b.WriteString("\n## Warnings\n")
		for _, w := range warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
	}
	b.WriteString(`
## Usage
1. Set your cloud credentials and a remote state backend (here: "terraform init -backend=false" you are expected to configure state separately).
2. Fill required inputs in variables.tf (shipped with defaults where possible).
3. Run: terraform init && terraform plan && terraform apply.
4. Run policy checks: ./tests/run-checks.sh

## Tests
- checkov / tfsec (if installed) — run via tests/run-checks.sh
`)
	return b.String()
}

// sortedKeys returns the provider set ordered by the request's Providers list
// (preserving user intent), then catalog order, then alphabetical.
func sortedKeys(used map[string]bool, catalogOrder, preferred []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if used[p] && !seen[p] {
			out = append(out, p)
			seen[p] = true
		}
	}
	for _, p := range preferred {
		add(p)
	}
	for _, p := range catalogOrder {
		add(p)
	}
	var rest []string
	for p := range used {
		if !seen[p] {
			rest = append(rest, p)
		}
	}
	sort.Strings(rest)
	for _, p := range rest {
		add(p)
	}
	return out
}

func collectWarnings(pkgs map[string]*pkg, providers []string) []string {
	var out []string
	for _, prov := range providers {
		out = append(out, pkgs[prov].warnings...)
	}
	return out
}

func finalOrderAs(order []string) []string { return order }

// moduleName disambiguates a module block/variable/output name when a bundle
// spans multiple providers (component names can collide, e.g. kms_key).
func moduleName(multi bool, provider, comp string) string {
	if multi {
		return provider + "_" + comp
	}
	return comp
}

func variableName(multi bool, provider, comp, variable string) string {
	if multi {
		return provider + "_" + comp + "_" + variable
	}
	return comp + "_" + variable
}

func outputName(multi bool, provider, comp, output string) string {
	if multi {
		return provider + "_" + comp + "_" + output
	}
	return comp + "_" + output
}

// inputExpr resolves a module variable input, wiring it to a dependency output
// when declared in metadata.yaml, otherwise a top-level variable.
func inputExpr(multi bool, provider string, pkgs map[string]*pkg, comp, variable string) string {
	p := pkgs[provider]
	rc := p.resolved[comp]
	expr := "var." + variableName(multi, provider, comp, variable)
	for _, w := range rc.component.Wiring {
		if w.Variable == variable {
			if _, ok := p.resolved[w.Module]; ok {
				expr = "module." + moduleName(multi, provider, w.Module) + "." + w.Output
			}
		}
	}
	return expr
}

const testRunnerScript = `#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if command -v checkov >/dev/null 2>&1; then
  echo "==> checkov"
  checkov -d . --quiet
else
  echo "checkov not installed (pip install checkov)"
fi

if command -v tfsec >/dev/null 2>&1; then
  echo "==> tfsec"
  tfsec .
else
  echo "tfsec not installed (brew install tfsec)"
fi
`
