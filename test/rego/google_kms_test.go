package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google/kms"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(googleKmsTestCases)
}

var googleKmsTestCases = testCases{
	"AVD-GCP-0065": {
		{
			name: "KMS key rotation period of 91 days",
			input: state.State{Google: google.Google{KMS: kms.KMS{
				KeyRings: []kms.KeyRing{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Keys: []kms.Key{
							{
								Metadata:              tunnelTypes.NewTestMetadata(),
								RotationPeriodSeconds: tunnelTypes.Int(7862400, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "KMS key rotation period of 30 days",
			input: state.State{Google: google.Google{KMS: kms.KMS{
				KeyRings: []kms.KeyRing{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Keys: []kms.Key{
							{
								Metadata:              tunnelTypes.NewTestMetadata(),
								RotationPeriodSeconds: tunnelTypes.Int(2592000, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
