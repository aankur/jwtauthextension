// Code generated by mdatagen. DO NOT EDIT.

package jwtauthextension

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"go.opentelemetry.io/collector/extension/extensiontest"
)

func TestComponentLifecycle(t *testing.T) {
	factory := NewFactory()

	cm, err := confmaptest.LoadConf("metadata.yaml")
	require.NoError(t, err)
	sub, err := cm.Sub("tests::config")
	cfg := &Config{
		Attribute: "authorization",
		JWTSecret: "foo",
	}

	require.NoError(t, err)
	require.NoError(t, sub.Unmarshal(&cfg))
	t.Run("shutdown", func(t *testing.T) {
		e, err := factory.Create(context.Background(), extensiontest.NewNopSettings(), cfg)
		require.NoError(t, err)
		err = e.Shutdown(context.Background())
		require.NoError(t, err)
	})
}
