package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure/database"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(azureDatabaseTestCases)
}

var azureDatabaseTestCases = testCases{
	"AVD-AZU-0028": {
		{
			name: "MS SQL server alerts for SQL injection disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								DisabledAlerts: []tunnelTypes.StringValue{
									tunnelTypes.String("Sql_Injection", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MS SQL server all alerts enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:       tunnelTypes.NewTestMetadata(),
								DisabledAlerts: []tunnelTypes.StringValue{},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0027": {
		{
			name: "MS SQL server extended audit policy not configured",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata:                 tunnelTypes.NewTestMetadata(),
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MS SQL server extended audit policy configured",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{
							{
								Metadata:        tunnelTypes.NewTestMetadata(),
								RetentionInDays: tunnelTypes.Int(6, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0020": {
		{
			name: "MariaDB server SSL not enforced",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:             tunnelTypes.NewTestMetadata(),
							EnableSSLEnforcement: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MySQL server SSL not enforced",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:             tunnelTypes.NewTestMetadata(),
							EnableSSLEnforcement: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server SSL not enforced",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:             tunnelTypes.NewTestMetadata(),
							EnableSSLEnforcement: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MariaDB server SSL enforced",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:             tunnelTypes.NewTestMetadata(),
							EnableSSLEnforcement: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MySQL server SSL enforced",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:             tunnelTypes.NewTestMetadata(),
							EnableSSLEnforcement: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "PostgreSQL server SSL enforced",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:             tunnelTypes.NewTestMetadata(),
							EnableSSLEnforcement: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0022": {
		{
			name: "MySQL server public access enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MariaDB server public access enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MS SQL server public access enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server public access enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MySQL server public access disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MariaDB server public access disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MS SQL server public access disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "PostgreSQL server public access disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0029": {
		{
			name: "MySQL server firewall allows public internet access",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: tunnelTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									StartIP:  tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
									EndIP:    tunnelTypes.String("255.255.255.255", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MySQL server firewall allows single public internet access",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: tunnelTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									StartIP:  tunnelTypes.String("8.8.8.8", tunnelTypes.NewTestMetadata()),
									EndIP:    tunnelTypes.String("8.8.8.8", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MS SQL server firewall allows public internet access",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: tunnelTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									StartIP:  tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
									EndIP:    tunnelTypes.String("255.255.255.255", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server firewall allows public internet access",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: tunnelTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									StartIP:  tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
									EndIP:    tunnelTypes.String("255.255.255.255", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MariaDB server firewall allows public internet access",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: tunnelTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									StartIP:  tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
									EndIP:    tunnelTypes.String("255.255.255.255", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MySQL server firewall allows access to Azure services",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: tunnelTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									StartIP:  tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
									EndIP:    tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MS SQL server firewall allows access to Azure services",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: tunnelTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									StartIP:  tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
									EndIP:    tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "PostgreSQL server firewall allows access to Azure services",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: tunnelTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									StartIP:  tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
									EndIP:    tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MariaDB server firewall allows access to Azure services",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: tunnelTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									StartIP:  tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
									EndIP:    tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0021": {
		{
			name: "PostgreSQL server connection throttling disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:             tunnelTypes.NewTestMetadata(),
							ConnectionThrottling: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server connection throttling enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:             tunnelTypes.NewTestMetadata(),
							ConnectionThrottling: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0024": {
		{
			name: "PostgreSQL server checkpoint logging disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:       tunnelTypes.NewTestMetadata(),
							LogCheckpoints: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server checkpoint logging enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:       tunnelTypes.NewTestMetadata(),
							LogCheckpoints: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0019": {
		{
			name: "PostgreSQL server connection logging disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:       tunnelTypes.NewTestMetadata(),
							LogConnections: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server connection logging enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:       tunnelTypes.NewTestMetadata(),
							LogConnections: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0025": {
		{
			name: "MS SQL server auditing policy with retention period of 30 days",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{
							{
								Metadata:        tunnelTypes.NewTestMetadata(),
								RetentionInDays: tunnelTypes.Int(30, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MS SQL server auditing policy with retention period of 90 days",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{
							{
								Metadata:        tunnelTypes.NewTestMetadata(),
								RetentionInDays: tunnelTypes.Int(90, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0026": {
		{
			name: "MS SQL server minimum TLS version 1.0",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          tunnelTypes.NewTestMetadata(),
							MinimumTLSVersion: tunnelTypes.String("1.0", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MySQL server minimum TLS version 1.0",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          tunnelTypes.NewTestMetadata(),
							MinimumTLSVersion: tunnelTypes.String("TLS1_0", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server minimum TLS version 1.0",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          tunnelTypes.NewTestMetadata(),
							MinimumTLSVersion: tunnelTypes.String("TLS1_0", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MS SQL server minimum TLS version 1.2",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          tunnelTypes.NewTestMetadata(),
							MinimumTLSVersion: tunnelTypes.String("1.2", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MySQL server minimum TLS version 1.2",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          tunnelTypes.NewTestMetadata(),
							MinimumTLSVersion: tunnelTypes.String("TLS1_2", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "PostgreSQL server minimum TLS version 1.2",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          tunnelTypes.NewTestMetadata(),
							MinimumTLSVersion: tunnelTypes.String("TLS1_2", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0018": {
		{
			name: "No email address provided for threat alerts",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:       tunnelTypes.NewTestMetadata(),
								EmailAddresses: []tunnelTypes.StringValue{},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Email address provided for threat alerts",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								EmailAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("sample@email.com", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0023": {
		{
			name: "MS SQL Server alert account admins disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:           tunnelTypes.NewTestMetadata(),
								EmailAccountAdmins: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MS SQL Server alert account admins enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:           tunnelTypes.NewTestMetadata(),
								EmailAccountAdmins: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
