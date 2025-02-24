package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google/bigquery"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(googleBigQueryTestCases)
}

var googleBigQueryTestCases = testCases{
	"AVD-GCP-0046": {
		{
			name: "positive result",
			input: state.State{Google: google.Google{BigQuery: bigquery.BigQuery{
				Datasets: []bigquery.Dataset{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						AccessGrants: []bigquery.AccessGrant{
							{
								SpecialGroup: tunnelTypes.String(
									bigquery.SpecialGroupAllAuthenticatedUsers,
									tunnelTypes.NewTestMetadata(),
								),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "negative result",
			input: state.State{Google: google.Google{BigQuery: bigquery.BigQuery{
				Datasets: []bigquery.Dataset{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						AccessGrants: []bigquery.AccessGrant{
							{
								SpecialGroup: tunnelTypes.String(
									"anotherGroup",
									tunnelTypes.NewTestMetadata(),
								),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
