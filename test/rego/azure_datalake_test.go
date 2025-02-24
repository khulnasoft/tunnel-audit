package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure/datalake"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(azureDataLakeTestCases)
}

var azureDataLakeTestCases = testCases{
	"AVD-AZU-0036": {
		{
			name: "unencrypted Data Lake store",
			input: state.State{Azure: azure.Azure{DataLake: datalake.DataLake{
				Stores: []datalake.Store{
					{
						Metadata:         tunnelTypes.NewTestMetadata(),
						EnableEncryption: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "encrypted Data Lake store",
			input: state.State{Azure: azure.Azure{DataLake: datalake.DataLake{
				Stores: []datalake.Store{
					{
						Metadata:         tunnelTypes.NewTestMetadata(),
						EnableEncryption: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
