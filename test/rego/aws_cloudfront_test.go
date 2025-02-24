package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/cloudfront"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsCloudfrontTestCases)
}

var awsCloudfrontTestCases = testCases{
	"AVD-AWS-0010": {
		{
			name: "CloudFront distribution missing logging configuration",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Logging: cloudfront.Logging{
							Metadata: tunnelTypes.NewTestMetadata(),
							Bucket:   tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "CloudFront distribution with logging configured",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Logging: cloudfront.Logging{
							Metadata: tunnelTypes.NewTestMetadata(),
							Bucket:   tunnelTypes.String("mylogs.s3.amazonaws.com", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0011": {
		{
			name: "CloudFront distribution missing WAF",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						WAFID:    tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "CloudFront distribution with WAF provided",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						WAFID:    tunnelTypes.String("waf_id", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0012": {
		{
			name: "CloudFront distribution default cache behaviour with allow all policy",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             tunnelTypes.NewTestMetadata(),
							ViewerProtocolPolicy: tunnelTypes.String(cloudfront.ViewerPolicyProtocolAllowAll, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "CloudFront distribution ordered cache behaviour with allow all policy",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             tunnelTypes.NewTestMetadata(),
							ViewerProtocolPolicy: tunnelTypes.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, tunnelTypes.NewTestMetadata()),
						},
						OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
							{
								Metadata:             tunnelTypes.NewTestMetadata(),
								ViewerProtocolPolicy: tunnelTypes.String(cloudfront.ViewerPolicyProtocolAllowAll, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "CloudFront distribution cache behaviours allowing HTTPS only",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             tunnelTypes.NewTestMetadata(),
							ViewerProtocolPolicy: tunnelTypes.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, tunnelTypes.NewTestMetadata()),
						},
						OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
							{
								Metadata:             tunnelTypes.NewTestMetadata(),
								ViewerProtocolPolicy: tunnelTypes.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0013": {
		{
			name: "CloudFront distribution using TLS v1.0",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:               tunnelTypes.NewTestMetadata(),
							MinimumProtocolVersion: tunnelTypes.String("TLSv1.0", tunnelTypes.NewTestMetadata()),
							SSLSupportMethod:       tunnelTypes.String("sni-only", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "CloudFront distribution using TLS v1.2",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:               tunnelTypes.NewTestMetadata(),
							MinimumProtocolVersion: tunnelTypes.String(cloudfront.ProtocolVersionTLS1_2, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "CloudFrontDefaultCertificate is true",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:                     tunnelTypes.NewTestMetadata(),
							MinimumProtocolVersion:       tunnelTypes.String("TLSv1.0", tunnelTypes.NewTestMetadata()),
							CloudfrontDefaultCertificate: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "SSLSupportMethod is not `sny-only`",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:               tunnelTypes.NewTestMetadata(),
							MinimumProtocolVersion: tunnelTypes.String("TLSv1.0", tunnelTypes.NewTestMetadata()),
							SSLSupportMethod:       tunnelTypes.String("vip", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
	},
}
