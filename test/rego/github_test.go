package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/github"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(githubTestCases)
}

var githubTestCases = testCases{
	"AVD-GIT-0004": {
		{
			name: "Require signed commits enabled for branch",
			input: state.State{GitHub: github.GitHub{BranchProtections: []github.BranchProtection{
				{
					Metadata:             tunnelTypes.NewTestMetadata(),
					RequireSignedCommits: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
		{
			name: "Require signed commits disabled for repository",
			input: state.State{GitHub: github.GitHub{BranchProtections: []github.BranchProtection{
				{
					Metadata:             tunnelTypes.NewTestMetadata(),
					RequireSignedCommits: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
	},
	"AVD-GIT-0003": {
		{
			name: "Vulnerability alerts enabled for repository",
			input: state.State{GitHub: github.GitHub{Repositories: []github.Repository{
				{
					Metadata:            tunnelTypes.NewTestMetadata(),
					VulnerabilityAlerts: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					Archived:            tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
		{
			name: "Vulnerability alerts disabled for repository",
			input: state.State{GitHub: github.GitHub{Repositories: []github.Repository{
				{
					Metadata:            tunnelTypes.NewTestMetadata(),
					VulnerabilityAlerts: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					Archived:            tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "Vulnerability alerts disabled for archived repository",
			input: state.State{GitHub: github.GitHub{Repositories: []github.Repository{
				{
					Metadata:            tunnelTypes.NewTestMetadata(),
					VulnerabilityAlerts: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					Archived:            tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-GIT-0002": {
		{
			name: "Github actions environment secret has plain text value",
			input: state.State{GitHub: github.GitHub{EnvironmentSecrets: []github.EnvironmentSecret{
				{
					Metadata:       tunnelTypes.NewTestMetadata(),
					PlainTextValue: tunnelTypes.String("sensitive secret string", tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "Github actions environment secret has no plain text value",
			input: state.State{GitHub: github.GitHub{EnvironmentSecrets: []github.EnvironmentSecret{
				{
					Metadata:       tunnelTypes.NewTestMetadata(),
					PlainTextValue: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-GIT-0001": {
		{
			name: "Public repository",
			input: state.State{GitHub: github.GitHub{Repositories: []github.Repository{
				{
					Metadata: tunnelTypes.NewTestMetadata(),
					Public:   tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "Private repository",
			input: state.State{GitHub: github.GitHub{Repositories: []github.Repository{
				{
					Metadata: tunnelTypes.NewTestMetadata(),
					Public:   tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
}
