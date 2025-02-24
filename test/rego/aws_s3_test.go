package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/cloudtrail"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/s3"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsS3TestCases)
}

var awsS3TestCases = testCases{
	"AVD-AWS-0086": {
		{
			name: "Public access block missing",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Public access block blocks public ACLs",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						PublicAccessBlock: &s3.PublicAccessBlock{
							Metadata:        tunnelTypes.NewTestMetadata(),
							BlockPublicACLs: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0087": {
		{
			name: "Public access block missing",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Public access block blocks public policies",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						PublicAccessBlock: &s3.PublicAccessBlock{
							Metadata:          tunnelTypes.NewTestMetadata(),
							BlockPublicPolicy: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0088": {
		{
			name: "Bucket encryption disabled",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: s3.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Bucket encryption enabled",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: s3.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0172": {
		{
			name: "S3 bucket with no cloudtrail logging",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "S3 bucket with WriteOnly cloudtrail logging (all of s3)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
						},
					}},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									ReadWriteType: tunnelTypes.String("WriteOnly", tunnelTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: tunnelTypes.NewTestMetadata(),
											Type:     tunnelTypes.String("AWS::S3::Object", tunnelTypes.NewTestMetadata()),
											Values: []tunnelTypes.StringValue{
												tunnelTypes.String("arn:aws:s3", tunnelTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				}},
			},
			expected: true,
		},
		{
			name: "S3 bucket with ReadOnly cloudtrail logging (all of s3)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									ReadWriteType: tunnelTypes.String("ReadOnly", tunnelTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: tunnelTypes.NewTestMetadata(),
											Type:     tunnelTypes.String("AWS::S3::Object", tunnelTypes.NewTestMetadata()),
											Values: []tunnelTypes.StringValue{
												tunnelTypes.String("arn:aws:s3", tunnelTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				}},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (all of s3)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
						},
					}},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									ReadWriteType: tunnelTypes.String("All", tunnelTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: tunnelTypes.NewTestMetadata(),
											Type:     tunnelTypes.String("AWS::S3::Object", tunnelTypes.NewTestMetadata()),
											Values: []tunnelTypes.StringValue{
												tunnelTypes.String("arn:aws:s3", tunnelTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				}},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only this bucket)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									ReadWriteType: tunnelTypes.String("All", tunnelTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: tunnelTypes.NewTestMetadata(),
											Type:     tunnelTypes.String("AWS::S3::Object", tunnelTypes.NewTestMetadata()),
											Values: []tunnelTypes.StringValue{
												tunnelTypes.String("arn:aws:s3:::test-bucket/", tunnelTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				}},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only another bucket)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									ReadWriteType: tunnelTypes.String("All", tunnelTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: tunnelTypes.NewTestMetadata(),
											Type:     tunnelTypes.String("AWS::S3::Object", tunnelTypes.NewTestMetadata()),
											Values: []tunnelTypes.StringValue{
												tunnelTypes.String("arn:aws:s3:::test-bucket2/", tunnelTypes.NewTestMetadata()),
											},
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
			name: "S3 bucket with 'All' cloudtrail logging (this bucket, missing slash)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									ReadWriteType: tunnelTypes.String("All", tunnelTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: tunnelTypes.NewTestMetadata(),
											Type:     tunnelTypes.String("AWS::S3::Object", tunnelTypes.NewTestMetadata()),
											Values: []tunnelTypes.StringValue{
												tunnelTypes.String("arn:aws:s3:::test-bucket", tunnelTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				}},
			},
			expected: true,
		},
	},
	"AVD-AWS-0171": {
		{
			name: "S3 bucket with no cloudtrail logging",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "S3 bucket with ReadOnly cloudtrail logging (all of s3)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									ReadWriteType: tunnelTypes.String("ReadOnly", tunnelTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: tunnelTypes.NewTestMetadata(),
											Type:     tunnelTypes.String("AWS::S3::Object", tunnelTypes.NewTestMetadata()),
											Values: []tunnelTypes.StringValue{
												tunnelTypes.String("arn:aws:s3", tunnelTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				},
			}},
			expected: true,
		},
		{
			name: "S3 bucket with WriteOnly cloudtrail logging (all of s3)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									ReadWriteType: tunnelTypes.String("WriteOnly", tunnelTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: tunnelTypes.NewTestMetadata(),
											Type:     tunnelTypes.String("AWS::S3::Object", tunnelTypes.NewTestMetadata()),
											Values: []tunnelTypes.StringValue{
												tunnelTypes.String("arn:aws:s3", tunnelTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (all of s3)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									ReadWriteType: tunnelTypes.String("All", tunnelTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: tunnelTypes.NewTestMetadata(),
											Type:     tunnelTypes.String("AWS::S3::Object", tunnelTypes.NewTestMetadata()),
											Values: []tunnelTypes.StringValue{
												tunnelTypes.String("arn:aws:s3", tunnelTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only this bucket)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									ReadWriteType: tunnelTypes.String("All", tunnelTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: tunnelTypes.NewTestMetadata(),
											Type:     tunnelTypes.String("AWS::S3::Object", tunnelTypes.NewTestMetadata()),
											Values: []tunnelTypes.StringValue{
												tunnelTypes.String("arn:aws:s3:::test-bucket/", tunnelTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only another bucket)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									ReadWriteType: tunnelTypes.String("All", tunnelTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: tunnelTypes.NewTestMetadata(),
											Type:     tunnelTypes.String("AWS::S3::Object", tunnelTypes.NewTestMetadata()),
											Values: []tunnelTypes.StringValue{
												tunnelTypes.String("arn:aws:s3:::test-bucket2/", tunnelTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				},
			}},
			expected: true,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (this bucket, missing slash)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Name:     tunnelTypes.String("test-bucket", tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									ReadWriteType: tunnelTypes.String("All", tunnelTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: tunnelTypes.NewTestMetadata(),
											Type:     tunnelTypes.String("AWS::S3::Object", tunnelTypes.NewTestMetadata()),
											Values: []tunnelTypes.StringValue{
												tunnelTypes.String("arn:aws:s3:::test-bucket", tunnelTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0090": {
		{
			name: "S3 bucket versioning disabled",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "S3 bucket versioning enabled",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0132": {
		{
			name: "S3 Bucket missing KMS key",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: s3.Encryption{
							Metadata: tunnelTypes.Metadata{},
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							KMSKeyId: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "S3 Bucket with KMS key",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: s3.Encryption{
							Metadata: tunnelTypes.Metadata{},
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							KMSKeyId: tunnelTypes.String("some-sort-of-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0091": {
		{
			name: "Public access block missing",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Public access block ignores public ACLs",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						PublicAccessBlock: &s3.PublicAccessBlock{
							Metadata:         tunnelTypes.NewTestMetadata(),
							IgnorePublicACLs: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0092": {
		{
			name: "positive result",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ACL:      tunnelTypes.String("public-read", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "negative result",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ACL:      tunnelTypes.String("private", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0093": {
		{
			name: "Public access block missing",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Public access block limiting access to buckets",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						PublicAccessBlock: &s3.PublicAccessBlock{
							Metadata:              tunnelTypes.NewTestMetadata(),
							RestrictPublicBuckets: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0170": {
		{
			name: "RequireMFADelete is not set",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata:  tunnelTypes.NewTestMetadata(),
							Enabled:   tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							MFADelete: tunnelTypes.BoolDefault(false, tunnelTypes.NewUnmanagedMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "RequireMFADelete is false",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata:  tunnelTypes.NewTestMetadata(),
							Enabled:   tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							MFADelete: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RequireMFADelete is true",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata:  tunnelTypes.NewTestMetadata(),
							Enabled:   tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							MFADelete: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0094": {
		{
			name: "Public access block missing",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Public access block present",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						PublicAccessBlock: &s3.PublicAccessBlock{
							Metadata: tunnelTypes.NewTestMetadata(),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
