package manual

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurrentPeriod_Quarterly(t *testing.T) {
	tests := []struct {
		name      string
		now       time.Time
		wantKey   string
		wantStart time.Time
		wantEnd   time.Time
	}{
		{
			name:      "Q1",
			now:       time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC),
			wantKey:   "2026-Q1",
			wantStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "Q2",
			now:       time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			wantKey:   "2026-Q2",
			wantStart: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "Q3",
			now:       time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC),
			wantKey:   "2026-Q3",
			wantStart: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "Q4",
			now:       time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
			wantKey:   "2026-Q4",
			wantStart: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := CurrentPeriod(FrequencyQuarterly, tt.now, "15d")
			require.NoError(t, err)
			assert.Equal(t, tt.wantKey, p.Key)
			assert.Equal(t, tt.wantStart, p.Start)
			assert.Equal(t, tt.wantEnd, p.End)
		})
	}
}

func TestCurrentPeriod_Yearly(t *testing.T) {
	now := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	p, err := CurrentPeriod(FrequencyYearly, now, "30d")
	require.NoError(t, err)

	assert.Equal(t, "2026", p.Key)
	assert.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), p.Start)
	assert.Equal(t, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), p.End)
	assert.Equal(t, time.Date(2027, 1, 31, 0, 0, 0, 0, time.UTC), p.GraceEnd)
}

func TestCurrentPeriod_Monthly(t *testing.T) {
	now := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	p, err := CurrentPeriod(FrequencyMonthly, now, "")
	require.NoError(t, err)

	assert.Equal(t, "2026-03", p.Key)
	assert.Equal(t, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), p.Start)
	assert.Equal(t, time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), p.End)
	assert.Equal(t, p.End, p.GraceEnd) // no grace
}

func TestCurrentPeriod_Daily(t *testing.T) {
	now := time.Date(2026, 3, 15, 14, 30, 0, 0, time.UTC)
	p, err := CurrentPeriod(FrequencyDaily, now, "")
	require.NoError(t, err)

	assert.Equal(t, "2026-03-15", p.Key)
	assert.Equal(t, time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), p.Start)
	assert.Equal(t, time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC), p.End)
}

func TestCurrentPeriod_Weekly(t *testing.T) {
	// 2026-03-16 is a Monday
	now := time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC) // Wednesday
	p, err := CurrentPeriod(FrequencyWeekly, now, "")
	require.NoError(t, err)

	assert.Equal(t, time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC), p.Start) // Monday
	assert.Equal(t, time.Date(2026, 3, 23, 0, 0, 0, 0, time.UTC), p.End)   // Next Monday
}

func TestCurrentPeriod_InvalidFrequency(t *testing.T) {
	_, err := CurrentPeriod("invalid", time.Now(), "")
	assert.Error(t, err)
}

func TestParseGracePeriod(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
		err   bool
	}{
		{"15d", 15 * 24 * time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"0d", 0, false},
		{"", 0, false},
		{"15", 0, true},
		{"abc", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseGracePeriod(tt.input)
			if tt.err {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestComputeTemporalStatus(t *testing.T) {
	period := Period{
		Key:      "2026-Q1",
		Start:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		End:      time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		GraceEnd: time.Date(2026, 4, 16, 0, 0, 0, 0, time.UTC),
	}

	tests := []struct {
		name        string
		now         time.Time
		hasEvidence bool
		want        TemporalStatus
	}{
		{"within period, no evidence", time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC), false, TemporalStatusWithinWindow},
		{"within period, has evidence", time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC), true, TemporalStatusWithinWindow},
		{"in grace period, no evidence", time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC), false, TemporalStatusWithinWindow},
		{"after grace, no evidence", time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), false, TemporalStatusOverdue},
		{"after grace, has evidence", time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), true, TemporalStatusWithinWindow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeTemporalStatus(&period, tt.now, tt.hasEvidence)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateUploadTime(t *testing.T) {
	period := Period{
		Start:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		End:      time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		GraceEnd: time.Date(2026, 4, 16, 0, 0, 0, 0, time.UTC),
	}

	// Retrospective: must be within [start, graceEnd]
	assert.NoError(t, ValidateUploadTime(&period, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), TemporalRuleRetrospective))
	assert.NoError(t, ValidateUploadTime(&period, time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC), TemporalRuleRetrospective))
	assert.Error(t, ValidateUploadTime(&period, time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC), TemporalRuleRetrospective))
	assert.Error(t, ValidateUploadTime(&period, time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), TemporalRuleRetrospective))

	// Anytime: must be before graceEnd
	assert.NoError(t, ValidateUploadTime(&period, time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC), TemporalRuleAnytime))
	assert.NoError(t, ValidateUploadTime(&period, time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC), TemporalRuleAnytime))
	assert.Error(t, ValidateUploadTime(&period, time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), TemporalRuleAnytime))
}
