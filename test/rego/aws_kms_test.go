package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/kms"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsKmsTestCases)
}

var awsKmsTestCases = testCases{
	"AVD-AWS-0065": {
		{
			name: "ENCRYPT_DECRYPT KMS Key with auto-rotation disabled",
			input: state.State{AWS: aws.AWS{KMS: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           tunnelTypes.String("ENCRYPT_DECRYPT", tunnelTypes.NewTestMetadata()),
						RotationEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ENCRYPT_DECRYPT KMS Key with auto-rotation enabled",
			input: state.State{AWS: aws.AWS{KMS: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           tunnelTypes.String("ENCRYPT_DECRYPT", tunnelTypes.NewTestMetadata()),
						RotationEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "SIGN_VERIFY KMS Key with auto-rotation disabled",
			input: state.State{AWS: aws.AWS{KMS: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           tunnelTypes.String(kms.KeyUsageSignAndVerify, tunnelTypes.NewTestMetadata()),
						RotationEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
