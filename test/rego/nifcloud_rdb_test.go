package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/nifcloud"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/nifcloud/rdb"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(nifcloudRdbTestCases)
}

var nifcloudRdbTestCases = testCases{
	"AVD-NIF-0012": {
		{
			name: "NIFCLOUD db security group with no description provided",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBSecurityGroups: []rdb.DBSecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD db security group with default description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBSecurityGroups: []rdb.DBSecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("Managed by Terraform", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD db security group with proper description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBSecurityGroups: []rdb.DBSecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("some proper description", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0010": {
		{
			name: "NIFCLOUD db instance with common private",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:  tunnelTypes.NewTestMetadata(),
						NetworkID: tunnelTypes.String("net-COMMON_PRIVATE", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD db instance with private LAN",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:  tunnelTypes.NewTestMetadata(),
						NetworkID: tunnelTypes.String("net-some-private-lan", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0008": {
		{
			name: "RDB Instance with public access enabled",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:     tunnelTypes.NewTestMetadata(),
						PublicAccess: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDB Instance with public access disabled",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:     tunnelTypes.NewTestMetadata(),
						PublicAccess: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0011": {
		{
			name: "NIFCLOUD ingress db security group rule with wildcard address",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBSecurityGroups: []rdb.DBSecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						CIDRs: []tunnelTypes.StringValue{
							tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD ingress db security group rule with private address",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBSecurityGroups: []rdb.DBSecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						CIDRs: []tunnelTypes.StringValue{
							tunnelTypes.String("10.0.0.0/16", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0009": {
		{
			name: "RDB Instance with 1 retention day (default)",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:                  tunnelTypes.NewTestMetadata(),
						BackupRetentionPeriodDays: tunnelTypes.Int(1, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDB Instance with 5 retention days",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:                  tunnelTypes.NewTestMetadata(),
						BackupRetentionPeriodDays: tunnelTypes.Int(5, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
