package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/elasticsearch"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsElasticsearchTestCases)
}

var awsElasticsearchTestCases = testCases{
	"AVD-AWS-0048": {
		{
			name: "Elasticsearch domain with at-rest encryption disabled",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						AtRestEncryption: elasticsearch.AtRestEncryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Elasticsearch domain with at-rest encryption enabled",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						AtRestEncryption: elasticsearch.AtRestEncryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0042": {
		{
			name: "Elasticsearch domain with audit logging disabled",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						LogPublishing: elasticsearch.LogPublishing{
							Metadata:     tunnelTypes.NewTestMetadata(),
							AuditEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Elasticsearch domain with audit logging enabled",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						LogPublishing: elasticsearch.LogPublishing{
							Metadata:     tunnelTypes.NewTestMetadata(),
							AuditEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0043": {
		{
			name: "Elasticsearch domain without in-transit encryption",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						TransitEncryption: elasticsearch.TransitEncryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Elasticsearch domain with in-transit encryption",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						TransitEncryption: elasticsearch.TransitEncryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0046": {
		{
			name: "Elasticsearch domain with enforce HTTPS disabled",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Endpoint: elasticsearch.Endpoint{
							Metadata:     tunnelTypes.NewTestMetadata(),
							EnforceHTTPS: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Elasticsearch domain with enforce HTTPS enabled",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Endpoint: elasticsearch.Endpoint{
							Metadata:     tunnelTypes.NewTestMetadata(),
							EnforceHTTPS: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0126": {
		{
			name: "Elasticsearch domain with TLS v1.0",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Endpoint: elasticsearch.Endpoint{
							Metadata:  tunnelTypes.NewTestMetadata(),
							TLSPolicy: tunnelTypes.String("Policy-Min-TLS-1-0-2019-07", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Elasticsearch domain with TLS v1.2",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Endpoint: elasticsearch.Endpoint{
							Metadata:  tunnelTypes.NewTestMetadata(),
							TLSPolicy: tunnelTypes.String("Policy-Min-TLS-1-2-2019-07", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
