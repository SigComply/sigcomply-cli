// Package storagetest serves in-memory object stores over the wire
// protocols of Google Cloud Storage (JSON and XML APIs) and Azure Blob
// Storage, so the vault and manual-evidence adapters can be tested through
// the real vendor SDKs: request building, pagination, response decoding
// and error mapping included.
//
// The in-memory fakes next to each adapter test the adapter's own logic
// behind its API interface. They never run the SDK code the adapter's
// realGCS / realAzure type calls, which is where a pagination or not-found
// bug would live. These servers cover that code without credentials or
// network access.
//
// Each server implements only the operations the adapters use: upload,
// download, and a flat prefix listing that returns at most PageSize
// objects per page. Any other request fails the test.
package storagetest

import (
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Object is one stored object.
type Object struct {
	Data     []byte
	Updated  time.Time
	Metadata map[string]string
}

// store is the state both servers share: objects by name, plus the page
// tokens each list request arrived with.
type store struct {
	t        testing.TB
	mu       sync.Mutex
	objects  map[string]Object
	pageSize int
	tokens   []string
	now      time.Time
}

func newStore(t testing.TB, pageSize int) *store {
	if pageSize < 1 {
		t.Fatalf("storagetest: page size must be at least 1, got %d", pageSize)
	}
	return &store{
		t: t, objects: map[string]Object{}, pageSize: pageSize,
		now: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
	}
}

// Put stores an object directly, bypassing the wire protocol.
func (s *store) Put(name string, data []byte, updated time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[name] = Object{Data: append([]byte(nil), data...), Updated: updated.UTC()}
}

// Get returns an object stored through either path.
func (s *store) Get(name string) (Object, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objects[name]
	return o, ok
}

// PageTokens returns the page token of every list request received, in
// order; the first page of a listing has an empty token.
func (s *store) PageTokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.tokens...)
}

func (s *store) put(name string, data []byte, meta map[string]string) Object {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := Object{Data: append([]byte(nil), data...), Updated: s.now, Metadata: meta}
	s.objects[name] = o
	return o
}

// page returns the names under prefix after token (exclusive), at most
// pageSize of them, and the token for the next page ("" when done). The
// token is the last name returned, which keeps the order stable.
func (s *store) page(prefix, token string) (names []string, objects []Object, next string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = append(s.tokens, token)
	var all []string
	for name := range s.objects {
		if strings.HasPrefix(name, prefix) && name > token {
			all = append(all, name)
		}
	}
	sort.Strings(all)
	if len(all) > s.pageSize {
		all = all[:s.pageSize]
		next = all[len(all)-1]
	}
	for _, name := range all {
		objects = append(objects, s.objects[name])
	}
	return all, objects, next
}
