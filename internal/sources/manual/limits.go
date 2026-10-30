package manual

import (
	"errors"
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
// backend reads object bodies through it or ReadAllLimitedSize
// (TestManualReadersCapReads).
func ReadAllLimited(r io.Reader, key string, limit int64) ([]byte, error) {
	return ReadAllLimitedSize(r, key, limit, 512)
}

// ReadAllLimitedSize is ReadAllLimited with the expected size known (a
// local file's stat): the buffer starts at size+1 bytes, so a file of
// that size is read with one allocation instead of io.ReadAll's
// doubling. A wrong size only costs extra allocations; the cap still
// holds.
func ReadAllLimitedSize(r io.Reader, key string, limit, size int64) ([]byte, error) {
	if size < 0 || size > limit {
		size = limit
	}
	buf := make([]byte, 0, size+1)
	lr := io.LimitReader(r, limit+1)
	for {
		if len(buf) == cap(buf) {
			buf = append(buf, 0)[:len(buf)]
		}
		n, err := lr.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if int64(len(buf)) > limit {
		return nil, &FileTooLargeError{Key: key, Limit: limit}
	}
	return buf, nil
}
