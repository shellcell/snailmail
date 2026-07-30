package s3host

import (
	"context"
	"errors"
	"io"
)

var (
	ErrNotFound     = errors.New("object not found")
	ErrPrecondition = errors.New("object precondition failed")
)

type Conditions struct {
	IfMatch     string
	IfNoneMatch bool
}

type ObjectInfo struct {
	ETag     string
	Size     int64
	SHA256   string
	Metadata map[string]string
}

type PutRequest struct {
	Key         string
	Body        io.Reader
	Size        int64
	SHA256      string
	ContentType string
	Metadata    map[string]string
	Conditions  Conditions
}

// ListedObject is what a bucket listing knows about an object.
//
// Deliberately less than Head reports. A listing carries the key, the size and
// the entity tag, and not the user metadata snailmail writes its digest into — so
// a caller that needs the digest has to head the object. A caller deciding what to
// collect does not, because the key says which release an object belongs to.
type ListedObject struct {
	Key  string
	Size int64
	ETag string
}

// maxListPage bounds one page of a listing. A bucket holding a year of daily
// publications has a large key count, and reading it in one response would be the
// same whole-in-memory failure as parsing an oversized lock. S3 itself caps a
// response at 1000 keys; this states the bound rather than inheriting it.
//
// Here rather than beside the AWS client because it is part of the contract every
// implementation holds to, including the one the tests use — and because the AWS
// file is excluded by the nos3 build, which would leave the bound undefined.
const maxListPage = 1000

// ListRequest asks for one page of keys.
type ListRequest struct {
	// Prefix bounds the listing. Empty would enumerate the bucket, which is never
	// what snailmail wants: every listing it performs is scoped to a repository.
	Prefix string
	// After resumes a listing, from the More token of a previous page. Empty
	// starts at the beginning.
	After string
	// Limit bounds one page. Zero means the client's default. A page is held in
	// memory, so this is the difference between a bounded read and the
	// whole-bucket-in-memory problem.
	Limit int
}

// ListResult is one page.
type ListResult struct {
	Objects []ListedObject
	// More is the token that resumes after this page, empty when the listing is
	// complete. A caller that ignores it sees a prefix of the truth, which is why
	// it is a token rather than a boolean.
	More string
}

// ObjectClient is the object store snailmail publishes through.
//
// Every operation but List addresses an object by a key the caller already knows,
// which is what lets a publication be verified without trusting a listing. List
// exists because collecting superseded state is the one thing that cannot work
// that way: nothing else can discover which releases are present.
//
// Note that List needs s3:ListBucket, which the other operations do not. See the
// README for what a publishing credential has to be allowed to do.
type ObjectClient interface {
	Head(context.Context, string) (ObjectInfo, error)
	Get(context.Context, string, int64) ([]byte, ObjectInfo, error)
	Put(context.Context, PutRequest) (ObjectInfo, error)
	CopyCreate(context.Context, string, string, int64, string) (ObjectInfo, error)
	Delete(context.Context, string, Conditions) error
	List(context.Context, ListRequest) (ListResult, error)
}
