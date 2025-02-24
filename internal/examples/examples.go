package examples

import (
	"strings"

	"github.com/aws-cloudformation/rain/cft/format"
	"github.com/aws-cloudformation/rain/cft/parse"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"gopkg.in/yaml.v3"

	tunnel_audit "github.com/khulnasoft/tunnel-audit"
	"github.com/khulnasoft/tunnel/pkg/iac/scan"
)

// GetCheckExamples retrieves examples for a given rule.
func GetCheckExamples(r scan.Rule) (CheckExamples, string, error) {
    path := getCheckExamplesPath(r)
    if path == "" {
        return CheckExamples{}, "", nil
    }

    b, err := tunnel_audit.EmbeddedPolicyFileSystem.ReadFile(path)
    if err != nil {
        return CheckExamples{}, "", err
    }

    var exmpls CheckExamples
    if err := yaml.Unmarshal(b, &exmpls); err != nil {
        return CheckExamples{}, "", err
    }

    return exmpls, path, nil
}

// getCheckExamplesPath determines the path to the examples for a given rule.
func getCheckExamplesPath(r scan.Rule) string {
    for _, eng := range []*scan.EngineMetadata{r.Terraform, r.CloudFormation} {
        if eng == nil {
            continue
        }

        paths := append(eng.BadExamples, eng.GoodExamples...)
        for _, path := range paths {
            if path != "" {
                return path
            }
        }
    }

    return ""
}

// ProviderExamples represents good and bad examples for a provider.
type ProviderExamples struct {
    Good blocks `yaml:"good,omitempty"`
    Bad  blocks `yaml:"bad,omitempty"`
}

// IsEmpty checks if there are no examples.
func (e ProviderExamples) IsEmpty() bool {
    return len(e.Good) == 0 && len(e.Bad) == 0
}

// CheckExamples maps provider names to their examples.
type CheckExamples map[string]ProviderExamples

// Format formats the examples for each provider.
func (e CheckExamples) Format() {
    for providerName, examples := range e {
        if formatFunc, ok := formatters[providerName]; ok {
            examples.Good.format(formatFunc)
            examples.Bad.format(formatFunc)
        }
        e[providerName] = examples
    }
}

// blockString represents a block of text.
type blockString string

// MarshalYAML customizes the YAML marshaling of blockString.
func (b blockString) MarshalYAML() (interface{}, error) {
    return &yaml.Node{
        Kind:  yaml.ScalarNode,
        Style: yaml.LiteralStyle,
        Value: strings.TrimSuffix(string(b), "\n"),
    }, nil
}

// blocks represents a list of blockStrings.
type blocks []blockString

// ToStrings converts blocks to a slice of strings.
func (b blocks) ToStrings() []string {
    res := make([]string, 0, len(b))
    for _, bs := range b {
        res = append(res, string(bs))
    }
    return res
}

// format applies a formatting function to each block.
func (b blocks) format(fn func(blockString) blockString) {
    for i, block := range b {
        b[i] = fn(block)
    }
}

var formatters = map[string]func(blockString) blockString{
    "terraform":      formatHCL,
    "cloudformation": formatCFT,
    "kubernetes":     formatYAML,
}

// formatHCL formats a blockString as HCL.
func formatHCL(b blockString) blockString {
    return blockString(hclwrite.Format([]byte(strings.Trim(string(b), " \n"))))
}

// formatCFT formats a blockString as CloudFormation YAML.
func formatCFT(b blockString) blockString {
    tmpl, err := parse.String(string(b))
    if err != nil {
        return blockString("Error parsing CFT: " + err.Error())
    }

    return blockString(format.CftToYaml(tmpl))
}

// formatYAML formats a blockString as YAML.
func formatYAML(b blockString) blockString {
    var v interface{}
    if err := yaml.Unmarshal([]byte(b), &v); err != nil {
        return blockString("Error unmarshaling YAML: " + err.Error())
    }
    ret, err := yaml.Marshal(v)
    if err != nil {
        return blockString("Error marshaling YAML: " + err.Error())
    }
    return blockString(ret)
}