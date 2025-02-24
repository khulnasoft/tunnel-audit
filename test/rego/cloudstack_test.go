package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/cloudstack"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/cloudstack/compute"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(cloudStackTestCases)
}

var cloudStackTestCases = testCases{
	"AVD-CLDSTK-0001": {
		{
			name: "Compute instance with sensitive information in user data",
			input: state.State{CloudStack: cloudstack.CloudStack{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						UserData: tunnelTypes.String(` export DATABASE_PASSWORD=\"SomeSortOfPassword\"`, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Compute instance with no sensitive information in user data",
			input: state.State{CloudStack: cloudstack.CloudStack{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						UserData: tunnelTypes.String(` export GREETING="Hello there"`, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
