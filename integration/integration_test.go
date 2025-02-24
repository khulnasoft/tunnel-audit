//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft/tunnel/pkg/commands"
	"github.com/khulnasoft/tunnel/pkg/types"
)

func runTunnel(t *testing.T, args []string) {
	defer viper.Reset()

	t.Helper()

	app := commands.NewApp()
	app.SetOut(io.Discard)
	app.SetArgs(args)

	err := app.ExecuteContext(context.TODO())
	require.NoError(t, err)
}

func readTunnelReport(t *testing.T, outputFile string) types.Report {
	t.Helper()

	out, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	var report types.Report
	require.NoError(t, json.Unmarshal(out, &report))
	return report
}
