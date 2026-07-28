// Package factscache memoises native package facts for the duration of one
// process.
//
// Parsing a package is the single most expensive step in a build: a Debian
// inspection decompresses the entire data archive, up to 256 MiB, only to total
// the installed size. A plan or apply re-derives the same facts several times
// over — once assembling the build input and again verifying the staged tree.
//
// Facts are keyed by format and content digest, which is safe because the
// digest is verified against the lock before anything is cached, and the bytes
// behind a verified digest cannot differ within a run. Nothing is persisted:
// an on-disk cache would have to be trusted across runs, and this is a tool
// whose value comes from re-deriving facts from bytes rather than believing a
// previous answer.
package factscache

import (
	"sync"

	"github.com/shellcell/snailmail/internal/domain"
)

// maxEntries bounds the cache so a very large workspace cannot grow it without
// limit. Facts are small, so this is generous; passing it simply stops caching
// rather than evicting, which keeps behaviour independent of insertion order.
const maxEntries = 4096

var cache struct {
	sync.RWMutex
	facts map[string]domain.PackageFacts
}

func key(format, digest string) string {
	return format + "\x00" + digest
}

// Lookup returns previously derived facts for verified content.
func Lookup(format, digest string) (domain.PackageFacts, bool) {
	if digest == "" {
		return domain.PackageFacts{}, false
	}
	cache.RLock()
	defer cache.RUnlock()
	facts, found := cache.facts[key(format, digest)]
	if !found {
		return domain.PackageFacts{}, false
	}
	return clone(facts), true
}

// Store records facts derived from content whose digest has been verified.
func Store(format, digest string, facts domain.PackageFacts) {
	if digest == "" {
		return
	}
	cache.Lock()
	defer cache.Unlock()
	if cache.facts == nil {
		cache.facts = make(map[string]domain.PackageFacts)
	}
	if len(cache.facts) >= maxEntries {
		return
	}
	cache.facts[key(format, digest)] = clone(facts)
}

// Reset drops every entry. Tests that rewrite content behind a digest use it.
func Reset() {
	cache.Lock()
	defer cache.Unlock()
	cache.facts = nil
}

// clone keeps the cached value independent of what a caller does with the
// slice and map it hands back.
func clone(facts domain.PackageFacts) domain.PackageFacts {
	facts.Requirements = append([]string(nil), facts.Requirements...)
	if facts.Fields != nil {
		fields := make(map[string]string, len(facts.Fields))
		for name, value := range facts.Fields {
			fields[name] = value
		}
		facts.Fields = fields
	}
	return facts
}
