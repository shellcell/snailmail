//go:build !nos3

package s3blob

import (
	"errors"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/shellcell/snailmail/blob"
)

func TestNormalizeAWSErrorDoesNotTreatMissingBucketAsMissingBlob(t *testing.T) {
	err := normalizeAWSError(&smithy.GenericAPIError{Code: "NoSuchBucket", Message: "missing bucket"})
	if errors.Is(err, blob.ErrNotFound) {
		t.Fatal("missing bucket was normalized as a missing blob")
	}
}

func TestValidateAWSEndpointRequiresHTTPSOutsideLoopback(t *testing.T) {
	if err := validateAWSEndpoint("http://objects.example"); err == nil {
		t.Fatal("plaintext remote endpoint was accepted")
	}
	for _, endpoint := range []string{"https://objects.example", "http://127.0.0.1:9000", "http://localhost:9000"} {
		if err := validateAWSEndpoint(endpoint); err != nil {
			t.Fatalf("endpoint %q rejected: %v", endpoint, err)
		}
	}
}
