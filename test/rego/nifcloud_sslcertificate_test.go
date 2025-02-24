package test

import (
	"time"

	"github.com/khulnasoft/tunnel/pkg/iac/providers/nifcloud"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/nifcloud/sslcertificate"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(nifcloudSslCertificateTestCases)
}

var nifcloudSslCertificateTestCases = testCases{
	"AVD-NIF-0006": {
		{
			name:     "No certs",
			input:    state.State{Nifcloud: nifcloud.Nifcloud{SSLCertificate: sslcertificate.SSLCertificate{}}},
			expected: false,
		},
		{
			name: "Valid cert",
			input: state.State{Nifcloud: nifcloud.Nifcloud{SSLCertificate: sslcertificate.SSLCertificate{
				ServerCertificates: []sslcertificate.ServerCertificate{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Expiration: tunnelTypes.Time(time.Now().Add(time.Hour), tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Expired cert",
			input: state.State{Nifcloud: nifcloud.Nifcloud{SSLCertificate: sslcertificate.SSLCertificate{
				ServerCertificates: []sslcertificate.ServerCertificate{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Expiration: tunnelTypes.Time(time.Now().Add(-time.Hour), tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
	},
}
