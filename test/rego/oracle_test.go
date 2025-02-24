package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/oracle"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(oracleTestCases)
}

var oracleTestCases = testCases{
	"AVD-OCI-0001": {
		{
			name: "Compute instance public reservation pool",
			input: state.State{Oracle: oracle.Oracle{Compute: oracle.Compute{
				AddressReservations: []oracle.AddressReservation{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Pool:     tunnelTypes.String("public-ippool", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Compute instance cloud reservation pool",
			input: state.State{Oracle: oracle.Oracle{Compute: oracle.Compute{
				AddressReservations: []oracle.AddressReservation{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Pool:     tunnelTypes.String("cloud-ippool", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
