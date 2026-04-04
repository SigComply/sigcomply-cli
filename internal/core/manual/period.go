package manual

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Period represents a time window for manual evidence collection.
type Period struct {
	Key      string    // "2026-Q1", "2026", "2026-03"
	Start    time.Time
	End      time.Time
	GraceEnd time.Time
}

// TemporalStatus indicates whether evidence is due, overdue, or not yet required.
type TemporalStatus string

const (
	TemporalStatusNotYetDue    TemporalStatus = "not_yet_due"
	TemporalStatusWithinWindow TemporalStatus = "within_window"
	TemporalStatusOverdue      TemporalStatus = "overdue"
)

// CurrentPeriod computes the current evidence period for a given frequency.
func CurrentPeriod(freq Frequency, now time.Time, gracePeriod string) (Period, error) {
	grace, err := ParseGracePeriod(gracePeriod)
	if err != nil {
		return Period{}, err
	}

	var p Period
	switch freq {
	case FrequencyDaily:
		start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		p = Period{
			Key:   start.Format("2006-01-02"),
			Start: start,
			End:   start.AddDate(0, 0, 1),
		}
	case FrequencyWeekly:
		// Week starts on Monday
		weekday := int(now.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		start := time.Date(now.Year(), now.Month(), now.Day()-(weekday-1), 0, 0, 0, 0, now.Location())
		p = Period{
			Key:   start.Format("2006-W") + fmt.Sprintf("%02d", weekNumber(start)),
			Start: start,
			End:   start.AddDate(0, 0, 7),
		}
	case FrequencyMonthly:
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		p = Period{
			Key:   start.Format("2006-01"),
			Start: start,
			End:   start.AddDate(0, 1, 0),
		}
	case FrequencyQuarterly:
		q := (int(now.Month()) - 1) / 3
		startMonth := time.Month(q*3 + 1)
		start := time.Date(now.Year(), startMonth, 1, 0, 0, 0, 0, now.Location())
		p = Period{
			Key:   fmt.Sprintf("%d-Q%d", now.Year(), q+1),
			Start: start,
			End:   start.AddDate(0, 3, 0),
		}
	case FrequencyYearly:
		start := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, now.Location())
		p = Period{
			Key:   fmt.Sprintf("%d", now.Year()),
			Start: start,
			End:   start.AddDate(1, 0, 0),
		}
	default:
		return Period{}, fmt.Errorf("unsupported frequency: %s", freq)
	}

	p.GraceEnd = p.End.Add(grace)
	return p, nil
}

// ParseGracePeriod parses a grace period string like "15d" into a time.Duration.
func ParseGracePeriod(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}

	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, "d") {
		return 0, fmt.Errorf("grace period must end with 'd' (days): %q", s)
	}

	days, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return 0, fmt.Errorf("invalid grace period %q: %w", s, err)
	}

	return time.Duration(days) * 24 * time.Hour, nil
}

// ComputeTemporalStatus determines whether evidence is due, overdue, or not yet required.
func ComputeTemporalStatus(period Period, now time.Time, hasEvidence bool) TemporalStatus {
	if hasEvidence {
		return TemporalStatusWithinWindow
	}

	if now.Before(period.End) {
		return TemporalStatusWithinWindow
	}

	if now.Before(period.GraceEnd) {
		return TemporalStatusWithinWindow
	}

	return TemporalStatusOverdue
}

// ValidateUploadTime checks if evidence was uploaded within a valid time for the period.
func ValidateUploadTime(period Period, uploadedAt time.Time, rule TemporalRule) error {
	switch rule {
	case TemporalRuleAnytime:
		// Evidence can be uploaded at any time, as long as it's not after grace period ends
		if uploadedAt.After(period.GraceEnd) {
			return fmt.Errorf("evidence uploaded after grace period ended (grace end: %s)", period.GraceEnd.Format(time.RFC3339))
		}
		return nil
	case TemporalRuleRetrospective:
		// Evidence must be uploaded during or after the period (not before it starts)
		if uploadedAt.Before(period.Start) {
			return fmt.Errorf("evidence uploaded before period started (period start: %s)", period.Start.Format(time.RFC3339))
		}
		if uploadedAt.After(period.GraceEnd) {
			return fmt.Errorf("evidence uploaded after grace period ended (grace end: %s)", period.GraceEnd.Format(time.RFC3339))
		}
		return nil
	default:
		return fmt.Errorf("unknown temporal rule: %s", rule)
	}
}

// weekNumber returns the ISO 8601 week number.
func weekNumber(t time.Time) int {
	_, week := t.ISOWeek()
	return week
}
