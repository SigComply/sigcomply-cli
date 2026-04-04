package sigcomply

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/iso27001"
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/core/config"
)

func TestCollectManualEvidence_Disabled(t *testing.T) {
	cfg := config.New()
	cfg.ManualEvidence.Enabled = false

	framework := soc2.New()
	ev, err := collectManualEvidence(context.Background(), cfg, framework)
	assert.NoError(t, err)
	assert.Nil(t, ev)
}

func TestCollectManualEvidence_NoManualProvider(t *testing.T) {
	cfg := config.New()
	cfg.ManualEvidence.Enabled = true

	framework := iso27001.New()
	ev, err := collectManualEvidence(context.Background(), cfg, framework)
	assert.NoError(t, err)
	assert.Nil(t, ev)
}

func TestGetFramework(t *testing.T) {
	tests := []struct {
		framework string
		valid     bool
	}{
		{"soc2", true},
		{"iso27001", true},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.framework, func(t *testing.T) {
			cfg := config.New()
			cfg.Framework = tt.framework
			fw, err := getFramework(cfg)
			if tt.valid {
				assert.NoError(t, err)
				assert.NotNil(t, fw)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
