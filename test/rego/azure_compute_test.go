package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure/compute"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(azureComputeTestCases)
}

var azureComputeTestCases = testCases{
	"AVD-AZU-0039": {
		{
			name: "Linux VM password authentication enabled",
			input: state.State{Azure: azure.Azure{Compute: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
							Metadata:                      tunnelTypes.NewTestMetadata(),
							DisablePasswordAuthentication: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Linux VM password authentication disabled",
			input: state.State{Azure: azure.Azure{Compute: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
							Metadata:                      tunnelTypes.NewTestMetadata(),
							DisablePasswordAuthentication: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0038": {
		{
			name: "Managed disk encryption disabled",
			input: state.State{Azure: azure.Azure{Compute: compute.Compute{
				ManagedDisks: []compute.ManagedDisk{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: compute.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Managed disk encryption enabled",
			input: state.State{Azure: azure.Azure{Compute: compute.Compute{
				ManagedDisks: []compute.ManagedDisk{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: compute.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0037": {
		{
			name: "Secrets in custom data",
			input: state.State{Azure: azure.Azure{Compute: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						VirtualMachine: compute.VirtualMachine{
							Metadata:   tunnelTypes.NewTestMetadata(),
							CustomData: tunnelTypes.String(`export DATABASE_PASSWORD=\"SomeSortOfPassword\"`, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "No secrets in custom data",
			input: state.State{Azure: azure.Azure{Compute: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						VirtualMachine: compute.VirtualMachine{
							Metadata:   tunnelTypes.NewTestMetadata(),
							CustomData: tunnelTypes.String(`export GREETING="Hello there"`, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
