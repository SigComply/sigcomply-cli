// Package log provides a minimal redaction-aware logger for the CLI.
// Plugins and core code MUST route diagnostic output through this
// logger so known PII shapes (emails, ARNs, UUIDs in identifier
// position, AWS access key IDs, JWTs) are stripped before they reach
// CI log storage. See docs/architecture/02-layers.md §Logging and
// redaction.
//
// The redaction patterns are deliberately conservative — they match
// canonical formats, not heuristic shapes. False negatives are
// preferable to false positives at this layer; the structural privacy
// boundary at L6 is the load-bearing guarantee.
package log

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sync"
)

// Level orders log severities from least to most urgent.
type Level int

// Level values.
const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// Logger emits redacted records to its sink. Construct via New. The
// zero value is not usable; New always returns a fully-initialized
// logger.
type Logger struct {
	mu      sync.Mutex
	sink    io.Writer
	minimum Level
	verbose bool
}

// New returns a logger writing to sink. If verbose is true, Debug
// records are emitted; otherwise Debug is suppressed. Redaction is
// always on — no flag disables it.
func New(sink io.Writer, verbose bool) *Logger {
	if sink == nil {
		sink = os.Stderr
	}
	minLevel := LevelInfo
	if verbose {
		minLevel = LevelDebug
	}
	return &Logger{sink: sink, minimum: minLevel, verbose: verbose}
}

// Default returns a logger writing to os.Stderr in non-verbose mode.
// Used by callers that don't need fine control.
func Default() *Logger { return New(os.Stderr, false) }

// Debugf records at LevelDebug; suppressed unless the logger is verbose.
func (l *Logger) Debugf(format string, args ...any) { l.logf(LevelDebug, format, args...) }

// Infof records at LevelInfo.
func (l *Logger) Infof(format string, args ...any) { l.logf(LevelInfo, format, args...) }

// Warnf records at LevelWarn.
func (l *Logger) Warnf(format string, args ...any) { l.logf(LevelWarn, format, args...) }

// Errorf records at LevelError.
func (l *Logger) Errorf(format string, args ...any) { l.logf(LevelError, format, args...) }

func (l *Logger) logf(lvl Level, format string, args ...any) {
	if lvl < l.minimum {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := Redact(fmt.Sprintf(format, args...))
	_, _ = fmt.Fprintf(l.sink, "[%s] %s\n", levelLabel(lvl), msg) //nolint:errcheck // log sink; nothing useful to do on failure
}

func levelLabel(l Level) string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "?"
	}
}

// Redaction patterns. Each replaces match → <redacted:type>. Order
// matters only insofar as more-specific patterns precede their
// supersets; below they are independent.
var (
	emailRE  = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	arnRE    = regexp.MustCompile(`arn:[a-z0-9-]+:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[a-zA-Z0-9:/_.-]+`)
	uuidRE   = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
	awsKeyRE = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)
	jwtRE    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
)

// Redact replaces canonical PII shapes in s with <redacted:type> tags.
// Used by Logger.log; exposed for callers that need to redact strings
// before storing them in structured fields elsewhere.
func Redact(s string) string {
	s = jwtRE.ReplaceAllString(s, "<redacted:token>")
	s = arnRE.ReplaceAllString(s, "<redacted:arn>")
	s = emailRE.ReplaceAllString(s, "<redacted:email>")
	s = awsKeyRE.ReplaceAllString(s, "<redacted:aws-key>")
	s = uuidRE.ReplaceAllString(s, "<redacted:uuid>")
	return s
}
