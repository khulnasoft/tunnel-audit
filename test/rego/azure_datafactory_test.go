package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure/datafactory"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(azureDataFactoryTestCases)
}

var azureDataFactoryTestCases = testCases{
	"AVD-AZU-0035": {
		{
			name: "Data Factory public access enabled",
			input: state.State{Azure: azure.Azure{DataFactory: datafactory.DataFactory{
				DataFactories: []datafactory.Factory{
					{
						Metadata:            tunnelTypes.NewTestMetadata(),
						EnablePublicNetwork: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Data Factory public access disabled",
			input: state.State{Azure: azure.Azure{DataFactory: datafactory.DataFactory{
				DataFactories: []datafactory.Factory{
					{
						Metadata:            tunnelTypes.NewTestMetadata(),
						EnablePublicNetwork: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
