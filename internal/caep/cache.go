package caep

import "sync"

// RevocationCache is a PEP's in-memory view of currently-revoked subjects, kept
// current by SETs pushed from the transmitter. Reads are on the hot path (every
// request), so it uses a read-write lock.
type RevocationCache struct {
	mu      sync.RWMutex
	revoked map[string]bool
}

// NewRevocationCache returns an empty cache.
func NewRevocationCache() *RevocationCache {
	return &RevocationCache{revoked: map[string]bool{}}
}

// Apply updates the cache from a received event.
func (c *RevocationCache) Apply(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch e.Type {
	case EventSessionRevoked:
		c.revoked[e.Subject] = true
	case EventSessionRestored:
		delete(c.revoked, e.Subject)
	}
}

// IsRevoked reports whether the subject's session is currently revoked. It
// satisfies the PEP's revocation-checker dependency.
func (c *RevocationCache) IsRevoked(subject string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.revoked[subject]
}
