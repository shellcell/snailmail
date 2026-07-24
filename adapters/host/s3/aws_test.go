package s3host

import (
	"errors"
	"testing"

	"github.com/aws/smithy-go"
)

func TestNormalizeAWSErrorDoesNotTreatMissingBucketAsMissingObject(t *testing.T) {
	err := normalizeAWSError(&smithy.GenericAPIError{Code: "NoSuchBucket", Message: "missing bucket"})
	if errors.Is(err, ErrNotFound) {
		t.Fatal("missing bucket was normalized as an empty repository")
	}
}

func TestNormalizeAWSErrorDoesNotTreatConditionalConflictAsPrecondition(t *testing.T) {
	err := normalizeAWSError(&smithy.GenericAPIError{Code: "ConditionalRequestConflict", Message: "retry the request"})
	if errors.Is(err, ErrPrecondition) {
		t.Fatal("conditional request conflict was normalized as a failed precondition")
	}
}
