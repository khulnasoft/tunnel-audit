package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google/sql"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(googleSqlTestCases)
}

var googleSqlTestCases = testCases{
	"AVD-GCP-0024": {
		{
			name: "Database instance backups disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:  tunnelTypes.NewTestMetadata(),
						IsReplica: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: tunnelTypes.NewTestMetadata(),
								Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Database instance backups enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:  tunnelTypes.NewTestMetadata(),
						IsReplica: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: tunnelTypes.NewTestMetadata(),
								Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Read replica does not require backups",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:  tunnelTypes.NewTestMetadata(),
						IsReplica: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: tunnelTypes.NewTestMetadata(),
								Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0014": {
		{
			name: "Instance temp files logging disabled for all files",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:        tunnelTypes.NewTestMetadata(),
								LogTempFileSize: tunnelTypes.Int(-1, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance temp files logging disabled for files smaller than 100KB",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:        tunnelTypes.NewTestMetadata(),
								LogTempFileSize: tunnelTypes.Int(100, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance temp files logging enabled for all files",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:        tunnelTypes.NewTestMetadata(),
								LogTempFileSize: tunnelTypes.Int(0, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0015": {
		{
			name: "DB instance TLS not required",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   tunnelTypes.NewTestMetadata(),
								RequireTLS: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DB instance TLS required",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   tunnelTypes.NewTestMetadata(),
								RequireTLS: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0026": {
		{
			name: "DB instance local file read access enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("MYSQL_5_6", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:    tunnelTypes.NewTestMetadata(),
								LocalInFile: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DB instance local file read access disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("MYSQL_5_6", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:    tunnelTypes.NewTestMetadata(),
								LocalInFile: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0023": {
		{
			name: "Instance contained database authentication enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("SQLSERVER_2017_STANDARD", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                        tunnelTypes.NewTestMetadata(),
								ContainedDatabaseAuthentication: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance contained database authentication disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("SQLSERVER_2017_STANDARD", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                        tunnelTypes.NewTestMetadata(),
								ContainedDatabaseAuthentication: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0019": {
		{
			name: "Instance cross database ownership chaining enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("SQLSERVER_2017_STANDARD", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                 tunnelTypes.NewTestMetadata(),
								CrossDBOwnershipChaining: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance cross database ownership chaining disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("SQLSERVER_2017_STANDARD", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                 tunnelTypes.NewTestMetadata(),
								CrossDBOwnershipChaining: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0017": {
		{
			name: "Instance settings set with IPv4 enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   tunnelTypes.NewTestMetadata(),
								EnableIPv4: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance settings set with IPv4 disabled but public CIDR in authorized networks",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   tunnelTypes.NewTestMetadata(),
								EnableIPv4: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								AuthorizedNetworks: []struct {
									Name tunnelTypes.StringValue
									CIDR tunnelTypes.StringValue
								}{
									{
										CIDR: tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance settings set with IPv4 disabled and private CIDR",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   tunnelTypes.NewTestMetadata(),
								EnableIPv4: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								AuthorizedNetworks: []struct {
									Name tunnelTypes.StringValue
									CIDR tunnelTypes.StringValue
								}{
									{
										CIDR: tunnelTypes.String("10.0.0.1/24", tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0025": {
		{
			name: "Instance checkpoint logging disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       tunnelTypes.NewTestMetadata(),
								LogCheckpoints: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance checkpoint logging enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       tunnelTypes.NewTestMetadata(),
								LogCheckpoints: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0016": {
		{
			name: "Instance connections logging disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       tunnelTypes.NewTestMetadata(),
								LogConnections: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance connections logging enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       tunnelTypes.NewTestMetadata(),
								LogConnections: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0022": {
		{
			name: "Instance disconnections logging disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:          tunnelTypes.NewTestMetadata(),
								LogDisconnections: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance disconnections logging enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:          tunnelTypes.NewTestMetadata(),
								LogDisconnections: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0018": {
		{
			name: "Instance minimum log severity set to PANIC",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       tunnelTypes.NewTestMetadata(),
								LogMinMessages: tunnelTypes.String("PANIC", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance minimum log severity set to ERROR",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       tunnelTypes.NewTestMetadata(),
								LogMinMessages: tunnelTypes.String("ERROR", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0020": {
		{
			name: "Instance lock waits logging disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:     tunnelTypes.NewTestMetadata(),
								LogLockWaits: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance lock waits logging enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:     tunnelTypes.NewTestMetadata(),
								LogLockWaits: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0021": {
		{
			name: "Instance logging enabled for all statements",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                tunnelTypes.NewTestMetadata(),
								LogMinDurationStatement: tunnelTypes.Int(0, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance logging disabled for all statements",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						DatabaseVersion: tunnelTypes.String("POSTGRES_12", tunnelTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: tunnelTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                tunnelTypes.NewTestMetadata(),
								LogMinDurationStatement: tunnelTypes.Int(-1, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
