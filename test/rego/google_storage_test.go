package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google/iam"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google/storage"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(googleStorageTestCases)
}

var googleStorageTestCases = testCases{
	"AVD-GCP-0066": {
		{
			name: "Storage bucket missing default kms key name",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: storage.BucketEncryption{
							Metadata:          tunnelTypes.NewTestMetadata(),
							DefaultKMSKeyName: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage bucket with default kms key name provided",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: storage.BucketEncryption{
							Metadata:          tunnelTypes.NewTestMetadata(),
							DefaultKMSKeyName: tunnelTypes.String("default-kms-key-name", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0002": {
		{
			name: "Uniform bucket level access disabled",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata:                       tunnelTypes.NewTestMetadata(),
						EnableUniformBucketLevelAccess: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Uniform bucket level access enabled",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata:                       tunnelTypes.NewTestMetadata(),
						EnableUniformBucketLevelAccess: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0001": {
		{
			name: "Members set to all authenticated users",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Members: []tunnelTypes.StringValue{
									tunnelTypes.String("allAuthenticatedUsers", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Members set to all users",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Member:   tunnelTypes.String("allUsers", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Members set to specific users",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Members: []tunnelTypes.StringValue{
									tunnelTypes.String("user:jane@example.com", tunnelTypes.NewTestMetadata()),
								},
							},
						},
						Members: []iam.Member{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Member:   tunnelTypes.String("user:john@example.com", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
