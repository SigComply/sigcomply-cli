package manual

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePath_DefaultTemplate(t *testing.T) {
	entry := &CatalogEntry{
		ID:        "access_review",
		Frequency: FrequencyQuarterly,
	}
	period := &Period{
		Key:   "2026-Q1",
		Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	path, err := ResolvePath(entry, "soc2", period)
	require.NoError(t, err)
	assert.Equal(t, "soc2/access_review/2026-Q1/evidence.pdf", path)
}

func TestResolvePath_CustomFilename(t *testing.T) {
	entry := &CatalogEntry{
		ID:        "access_review",
		Frequency: FrequencyQuarterly,
		Filename:  "access-review.pdf",
	}
	period := &Period{
		Key:   "2026-Q1",
		Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	path, err := ResolvePath(entry, "soc2", period)
	require.NoError(t, err)
	assert.Equal(t, "soc2/access_review/2026-Q1/access-review.pdf", path)
}

func TestResolvePath_AnnualWithYearPlaceholder(t *testing.T) {
	entry := &CatalogEntry{
		ID:           "security_training",
		Frequency:    FrequencyYearly,
		PathTemplate: "shared/{evidence_id}/{year}/{filename}",
	}
	period := &Period{
		Key:   "2026",
		Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	path, err := ResolvePath(entry, "soc2", period)
	require.NoError(t, err)
	assert.Equal(t, "shared/security_training/2026/evidence.pdf", path)
}

func TestResolvePath_QuarterPlaceholder(t *testing.T) {
	entry := &CatalogEntry{
		ID:           "access_review",
		Frequency:    FrequencyQuarterly,
		PathTemplate: "{framework}/{evidence_id}/{year}-{quarter}/{filename}",
	}
	period := &Period{
		Key:   "2026-Q2",
		Start: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	}

	path, err := ResolvePath(entry, "soc2", period)
	require.NoError(t, err)
	assert.Equal(t, "soc2/access_review/2026-Q2/evidence.pdf", path)
}

func TestResolvePath_MonthPlaceholder(t *testing.T) {
	entry := &CatalogEntry{
		ID:           "monthly_review",
		Frequency:    FrequencyMonthly,
		PathTemplate: "{framework}/{evidence_id}/{year}-{month}/{filename}",
	}
	period := &Period{
		Key:   "2026-03",
		Start: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
	}

	path, err := ResolvePath(entry, "soc2", period)
	require.NoError(t, err)
	assert.Equal(t, "soc2/monthly_review/2026-03/evidence.pdf", path)
}

func TestResolvePath_QuarterOnAnnualPolicyErrors(t *testing.T) {
	entry := &CatalogEntry{
		ID:           "annual_thing",
		Frequency:    FrequencyYearly,
		PathTemplate: "{framework}/{evidence_id}/{quarter}/{filename}",
	}
	period := &Period{
		Key:   "2026",
		Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	_, err := ResolvePath(entry, "soc2", period)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quarter")
}

func TestResolvePath_RejectsTraversal(t *testing.T) {
	entry := &CatalogEntry{
		ID:           "x",
		Frequency:    FrequencyYearly,
		PathTemplate: "../{evidence_id}/{filename}",
	}
	period := &Period{
		Key:   "2026",
		Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	_, err := ResolvePath(entry, "soc2", period)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "..")
}

func TestResolvePath_RejectsLeadingSlash(t *testing.T) {
	entry := &CatalogEntry{
		ID:           "x",
		Frequency:    FrequencyYearly,
		PathTemplate: "/abs/{evidence_id}/{filename}",
	}
	period := &Period{
		Key:   "2026",
		Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	_, err := ResolvePath(entry, "soc2", period)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/")
}

func TestResolvePath_RejectsNonPDFFilename(t *testing.T) {
	entry := &CatalogEntry{
		ID:        "x",
		Frequency: FrequencyYearly,
		Filename:  "evidence.txt",
	}
	period := &Period{
		Key:   "2026",
		Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	_, err := ResolvePath(entry, "soc2", period)
	require.Error(t, err)
	assert.Contains(t, err.Error(), ".pdf")
}

func TestResolvePath_RejectsTemplateNotEndingInPDF(t *testing.T) {
	entry := &CatalogEntry{
		ID:           "x",
		Frequency:    FrequencyYearly,
		PathTemplate: "{framework}/{evidence_id}/{period}/data.txt",
	}
	period := &Period{
		Key:   "2026",
		Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	_, err := ResolvePath(entry, "soc2", period)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), ".pdf"))
}
