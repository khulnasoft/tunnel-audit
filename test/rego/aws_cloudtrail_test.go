package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/cloudtrail"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/s3"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsCloudTrailTestCases)
}

var awsCloudTrailTestCases = testCases{
	"AVD-AWS-0014": {
		{
			name: "AWS CloudTrail not enabled across all regions",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:      tunnelTypes.NewTestMetadata(),
						IsMultiRegion: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS CloudTrail enabled across all regions",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:      tunnelTypes.NewTestMetadata(),
						IsMultiRegion: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0016": {
		{
			name: "AWS CloudTrail without logfile validation",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                tunnelTypes.NewTestMetadata(),
						EnableLogFileValidation: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS CloudTrail with logfile validation enabled",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                tunnelTypes.NewTestMetadata(),
						EnableLogFileValidation: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0015": {
		{
			name: "AWS CloudTrail without CMK",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS CloudTrail with CMK",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						KMSKeyID: tunnelTypes.String("some-kms-key", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0162": {
		{
			name: "Trail has cloudwatch configured",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  tunnelTypes.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:logs:us-east-1:123456789012:log-group:my-log-group", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Trail does not have cloudwatch configured",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  tunnelTypes.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0161": {
		{
			name: "Trail has bucket with no public access",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							BucketName: tunnelTypes.String("my-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("my-bucket", tunnelTypes.NewTestMetadata()),
							ACL:      tunnelTypes.String("private", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Trail has bucket with public access",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							BucketName: tunnelTypes.String("my-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("my-bucket", tunnelTypes.NewTestMetadata()),
							ACL:      tunnelTypes.String("public-read", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0163": {
		{
			name: "Trail has bucket with logging enabled",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							BucketName: tunnelTypes.String("my-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("my-bucket", tunnelTypes.NewTestMetadata()),
							Logging: s3.Logging{
								Metadata: tunnelTypes.NewTestMetadata(),
								Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Trail has bucket without logging enabled",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							BucketName: tunnelTypes.String("my-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("my-bucket", tunnelTypes.NewTestMetadata()),
							Logging: s3.Logging{
								Metadata: tunnelTypes.NewTestMetadata(),
								Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
}
