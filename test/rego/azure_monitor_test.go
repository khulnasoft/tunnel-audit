package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure/monitor"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(azureMonitorTestCases)
}

var azureMonitorTestCases = testCases{
	"AVD-AZU-0031": {
		{
			name: "Log retention policy disabled",
			input: state.State{Azure: azure.Azure{Monitor: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RetentionPolicy: monitor.RetentionPolicy{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							Days:     tunnelTypes.Int(365, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Log retention policy enabled for 90 days",
			input: state.State{Azure: azure.Azure{Monitor: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RetentionPolicy: monitor.RetentionPolicy{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Days:     tunnelTypes.Int(90, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Log retention policy enabled for 365 days",
			input: state.State{Azure: azure.Azure{Monitor: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RetentionPolicy: monitor.RetentionPolicy{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Days:     tunnelTypes.Int(365, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0033": {
		{
			name: "Log profile captures only write activities",
			input: state.State{Azure: azure.Azure{Monitor: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Categories: []tunnelTypes.StringValue{
							tunnelTypes.String("Write", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Log profile captures action, write, delete activities",
			input: state.State{Azure: azure.Azure{Monitor: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Categories: []tunnelTypes.StringValue{
							tunnelTypes.String("Action", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("Write", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("Delete", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0032": {
		{
			name: "Log profile captures only eastern US region",
			input: state.State{Azure: azure.Azure{Monitor: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Locations: []tunnelTypes.StringValue{
							tunnelTypes.String("eastus", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Log profile captures all regions",
			input: state.State{Azure: azure.Azure{Monitor: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Locations: []tunnelTypes.StringValue{
							tunnelTypes.String("eastus", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("eastus2", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("southcentralus", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("westus2", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("westus3", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("australiaeast", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("southeastasia", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("northeurope", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("swedencentral", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("uksouth", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("westeurope", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("centralus", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("northcentralus", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("westus", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("southafricanorth", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("centralindia", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("eastasia", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("japaneast", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("jioindiawest", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("koreacentral", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("canadacentral", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("francecentral", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("germanywestcentral", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("norwayeast", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("switzerlandnorth", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("uaenorth", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("brazilsouth", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("centralusstage", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("eastusstage", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("eastus2stage", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("northcentralusstage", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("southcentralusstage", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("westusstage", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("westus2stage", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("asia", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("asiapacific", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("australia", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("brazil", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("canada", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("europe", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("global", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("india", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("japan", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("uk", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("unitedstates", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("eastasiastage", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("southeastasiastage", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("centraluseuap", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("eastus2euap", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("westcentralus", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("southafricawest", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("australiacentral", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("australiacentral2", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("australiasoutheast", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("japanwest", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("jioindiacentral", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("koreasouth", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("southindia", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("westindia", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("canadaeast", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("francesouth", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("germanynorth", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("norwaywest", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("swedensouth", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("switzerlandwest", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("ukwest", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("uaecentral", tunnelTypes.NewTestMetadata()),
							tunnelTypes.String("brazilsoutheast", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
