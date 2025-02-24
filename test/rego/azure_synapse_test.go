package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure/synapse"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(azureSynapseTestCases)
}

var azureSynapseTestCases = testCases{
	"AVD-AZU-0034": {
		{
			name: "Synapse workspace managed VN disabled",
			input: state.State{Azure: azure.Azure{Synapse: synapse.Synapse{
				Workspaces: []synapse.Workspace{
					{
						Metadata:                    tunnelTypes.NewTestMetadata(),
						EnableManagedVirtualNetwork: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Synapse workspace managed VN enabled",
			input: state.State{Azure: azure.Azure{Synapse: synapse.Synapse{
				Workspaces: []synapse.Workspace{
					{
						Metadata:                    tunnelTypes.NewTestMetadata(),
						EnableManagedVirtualNetwork: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
