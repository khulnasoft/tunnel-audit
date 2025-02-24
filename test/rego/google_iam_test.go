package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google/iam"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(googleIamTestCases)
}

var googleIamTestCases = testCases{
	"AVD-GCP-0068": {
		{
			name: "Workload identity pool without condition",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				WorkloadIdentityPoolProviders: []iam.WorkloadIdentityPoolProvider{
					{
						Metadata:                       tunnelTypes.NewTestMetadata(),
						WorkloadIdentityPoolId:         tunnelTypes.String("example-pool", tunnelTypes.NewTestMetadata()),
						WorkloadIdentityPoolProviderId: tunnelTypes.String("example-provider", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Workload identity pool with empty condition",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				WorkloadIdentityPoolProviders: []iam.WorkloadIdentityPoolProvider{
					{
						Metadata:                       tunnelTypes.NewTestMetadata(),
						WorkloadIdentityPoolId:         tunnelTypes.String("example-pool", tunnelTypes.NewTestMetadata()),
						WorkloadIdentityPoolProviderId: tunnelTypes.String("example-provider", tunnelTypes.NewTestMetadata()),
						AttributeCondition:             tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Workload identity pool with non-empty condition",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				WorkloadIdentityPoolProviders: []iam.WorkloadIdentityPoolProvider{
					{
						Metadata:                       tunnelTypes.NewTestMetadata(),
						WorkloadIdentityPoolId:         tunnelTypes.String("example-pool", tunnelTypes.NewTestMetadata()),
						WorkloadIdentityPoolProviderId: tunnelTypes.String("example-provider", tunnelTypes.NewTestMetadata()),
						AttributeCondition:             tunnelTypes.String("assertion.repository_owner=='your-github-organization'", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0010": {
		{
			name: "Project automatic network creation enabled",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata:          tunnelTypes.NewTestMetadata(),
						AutoCreateNetwork: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Project automatic network creation enabled #2",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata:          tunnelTypes.NewTestMetadata(),
						AutoCreateNetwork: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
					{
						Metadata:          tunnelTypes.NewTestMetadata(),
						AutoCreateNetwork: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Project automatic network creation disabled",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata:          tunnelTypes.NewTestMetadata(),
						AutoCreateNetwork: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0004": {
		{
			name: "Default service account enabled",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata:              tunnelTypes.NewTestMetadata(),
								DefaultServiceAccount: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								Member:                tunnelTypes.String("proper@email.com", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Default service account disabled but default account data provided",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata:              tunnelTypes.NewTestMetadata(),
								DefaultServiceAccount: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Member:                tunnelTypes.String("123-compute@developer.gserviceaccount.com", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Default service account disabled but default account data provided #2",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata:                      tunnelTypes.NewTestMetadata(),
								IncludesDefaultServiceAccount: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Members: []tunnelTypes.StringValue{
									tunnelTypes.String("123-compute@developer.gserviceaccount.com", tunnelTypes.NewTestMetadata())},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Default service account disabled and proper account data provided",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata:              tunnelTypes.NewTestMetadata(),
								DefaultServiceAccount: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Member:                tunnelTypes.String("proper@email.com", tunnelTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata:                      tunnelTypes.NewTestMetadata(),
								IncludesDefaultServiceAccount: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Members: []tunnelTypes.StringValue{
									tunnelTypes.String("proper@account.com", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0005": {
		{
			name: "Member role set to service account user",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/iam.serviceAccountUser", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Binding role set to service account token creator",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata:                      tunnelTypes.NewTestMetadata(),
								IncludesDefaultServiceAccount: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Role:                          tunnelTypes.String("roles/iam.serviceAccountTokenCreator", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Member role set to something particular",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/nothingInParticular", tunnelTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata:                      tunnelTypes.NewTestMetadata(),
								IncludesDefaultServiceAccount: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Role:                          tunnelTypes.String("roles/nothingInParticular", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0008": {
		{
			name: "Default service account disabled but default account provided",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata:                      tunnelTypes.NewTestMetadata(),
								IncludesDefaultServiceAccount: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Members: []tunnelTypes.StringValue{
									tunnelTypes.String("123-compute@developer.gserviceaccount.com", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Default service account enabled",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata:              tunnelTypes.NewTestMetadata(),
								Member:                tunnelTypes.String("proper@email.com", tunnelTypes.NewTestMetadata()),
								DefaultServiceAccount: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Default service account disabled and proper account provided",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata:              tunnelTypes.NewTestMetadata(),
								Member:                tunnelTypes.String("proper@email.com", tunnelTypes.NewTestMetadata()),
								DefaultServiceAccount: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata:                      tunnelTypes.NewTestMetadata(),
								IncludesDefaultServiceAccount: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Members: []tunnelTypes.StringValue{
									tunnelTypes.String("proper@email.com", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0009": {
		{
			name: "Member role set to service account user",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/iam.serviceAccountUser", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Member role set to service account token creator",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/iam.serviceAccountTokenCreator", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},

		{
			name: "Member roles custom set",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/some-custom-role", tunnelTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/some-custom-role", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0007": {
		{
			name: "Service account granted owner role",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/owner", tunnelTypes.NewTestMetadata()),
								Member:   tunnelTypes.String("serviceAccount:${google_service_account.test.email}", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Service account granted editor role",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/editor", tunnelTypes.NewTestMetadata()),
								Members: []tunnelTypes.StringValue{
									tunnelTypes.String("serviceAccount:${google_service_account.test.email}", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "No service account with excessive privileges",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/owner", tunnelTypes.NewTestMetadata()),
								Member:   tunnelTypes.String("proper@email.com", tunnelTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/logging.logWriter", tunnelTypes.NewTestMetadata()),
								Members: []tunnelTypes.StringValue{
									tunnelTypes.String("serviceAccount:${google_service_account.test.email}", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0006": {
		{
			name: "Default service account disabled but default account used",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata:              tunnelTypes.NewTestMetadata(),
								DefaultServiceAccount: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Member:                tunnelTypes.String("123-compute@developer.gserviceaccount.com", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Default account enabled",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata:                      tunnelTypes.NewTestMetadata(),
								IncludesDefaultServiceAccount: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Default accounts disabled and proper accounts provided",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata:              tunnelTypes.NewTestMetadata(),
								DefaultServiceAccount: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Member:                tunnelTypes.String("proper@email.com", tunnelTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata:                      tunnelTypes.NewTestMetadata(),
								IncludesDefaultServiceAccount: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Members: []tunnelTypes.StringValue{
									tunnelTypes.String("proper@email.com", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0011": {
		{
			name: "Project member role set to service account user",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/iam.serviceAccountUser", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Project member role set to service account token creator",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/iam.serviceAccountTokenCreator", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Project members set to custom roles",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/specific-role", tunnelTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Role:     tunnelTypes.String("roles/specific-role", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0003": {
		{
			name: "Permissions granted to users",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Member:   tunnelTypes.String("user:test@example.com", tunnelTypes.NewTestMetadata()),
								Role:     tunnelTypes.String("some-role", tunnelTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Members: []tunnelTypes.StringValue{
									tunnelTypes.String("user:test@example.com", tunnelTypes.NewTestMetadata()),
								},
								Role: tunnelTypes.String("some-role", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Permissions granted to users #2",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Member:   tunnelTypes.String("user:test@example.com", tunnelTypes.NewTestMetadata()),
								Role:     tunnelTypes.String("some-role", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Permissions granted to users #3",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Member:   tunnelTypes.String("user:test@example.com", tunnelTypes.NewTestMetadata()),
								Role:     tunnelTypes.String("some-role", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Permissions granted to users #4",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Members: []tunnelTypes.StringValue{
									tunnelTypes.String("user:test@example.com", tunnelTypes.NewTestMetadata()),
								},
								Role: tunnelTypes.String("some-role", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Permissions granted on groups",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Member:   tunnelTypes.String("group:test@example.com", tunnelTypes.NewTestMetadata()),
								Role:     tunnelTypes.String("some-role", tunnelTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Members: []tunnelTypes.StringValue{
									tunnelTypes.String("group:test@example.com", tunnelTypes.NewTestMetadata()),
								},
								Role: tunnelTypes.String("some-role", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
				Folders: []iam.Folder{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Members: []tunnelTypes.StringValue{
									tunnelTypes.String("group:test@example.com", tunnelTypes.NewTestMetadata()),
								},
								Role: tunnelTypes.String("some-role", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
