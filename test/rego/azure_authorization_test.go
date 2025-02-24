package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure/authorization"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(azureAuthorizationTestCases)
}

var azureAuthorizationTestCases = testCases{
	"AVD-AZU-0030": {
		{
			name: "Wildcard action with all scopes",
			input: state.State{Azure: azure.Azure{Authorization: authorization.Authorization{
				RoleDefinitions: []authorization.RoleDefinition{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Permissions: []authorization.Permission{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Actions: []tunnelTypes.StringValue{
									tunnelTypes.String("*", tunnelTypes.NewTestMetadata()),
								},
							},
						},
						AssignableScopes: []tunnelTypes.StringValue{
							tunnelTypes.String("/", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Wildcard action with specific scope",
			input: state.State{Azure: azure.Azure{Authorization: authorization.Authorization{
				RoleDefinitions: []authorization.RoleDefinition{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Permissions: []authorization.Permission{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Actions: []tunnelTypes.StringValue{
									tunnelTypes.String("*", tunnelTypes.NewTestMetadata()),
								},
							},
						},
						AssignableScopes: []tunnelTypes.StringValue{
							tunnelTypes.String("proper-scope", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
