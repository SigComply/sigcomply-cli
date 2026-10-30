package manual

import (
	"fmt"
	"io"
)

// MaxFileBytes is the largest single evidence file the CLI reads, from
// any backend. Every file is held in memory to hash, convert and merge
// it, so an unbounded read lets one object (or a misbehaving endpoint
// that never ends its body) exhaust the CI runner's memory. 100 MB is
// several times the size of a long scanned audit report.
const MaxFileBytes int64 = 100 << 20

// FileTooLargeError is returned by a Reader's Get when the file is
// larger than the cap. The plugin turns it into a file_too_large
// validation failure for that policy, not a transport error.
type FileTooLargeError struct {
	Key   string
	Limit int64
}

func (e *FileTooLargeError) Error() string {
	return fmt.Sprintf("manual.pdf: %s is larger than the %d-byte limit", e.Key, e.Limit)
}

// Retryable implements sources.RetryableError: the file will be just as
// large on a second attempt.
func (e *FileTooLargeError) Retryable() bool { return false }

// ReadAllLimited reads r to the end, but no more than limit bytes; a
// longer stream returns FileTooLargeError naming key. Every Reader
// backend reads object bodies through it (TestManualReadersCapReads).
func ReadAllLimited(r io.Reader, key string, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &FileTooLargeError{Key: key, Limit: limit}
	}
	return data, nil
}
