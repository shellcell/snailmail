//go:build !nos3

package s3host

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	transport "github.com/aws/smithy-go/transport/http"
	"github.com/shellcell/snailmail/host"

	"github.com/shellcell/snailmail/internal/hexdigest"
)

type AWSClient struct {
	client *s3.Client
	bucket string
}

func NewAWS(ctx context.Context, repository host.Repository, brokers ...host.CredentialBroker) (*Adapter, error) {
	if err := validateRepository(repository); err != nil {
		return nil, err
	}
	options := []func(*awsconfig.LoadOptions) error{}
	if repository.Region != "" {
		options = append(options, awsconfig.WithRegion(repository.Region))
	}
	configuration, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	client := s3.NewFromConfig(configuration, func(options *s3.Options) {
		options.UsePathStyle = repository.UsePathStyle
		if repository.Endpoint != "" {
			options.BaseEndpoint = aws.String(repository.Endpoint)
		}
	})
	return New(&AWSClient{client: client, bucket: repository.Bucket}, brokers...), nil
}

func (client *AWSClient) Head(ctx context.Context, key string) (ObjectInfo, error) {
	result, err := client.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &client.bucket, Key: &key, ChecksumMode: types.ChecksumModeEnabled,
	})
	if err != nil {
		return ObjectInfo{}, normalizeAWSError(err)
	}
	return ObjectInfo{
		ETag: aws.ToString(result.ETag), Size: aws.ToInt64(result.ContentLength),
		SHA256: hexdigest.FromBase64(aws.ToString(result.ChecksumSHA256)), Metadata: result.Metadata,
	}, nil
}

func (client *AWSClient) List(ctx context.Context, request ListRequest) (ListResult, error) {
	if request.Prefix == "" {
		// Refused rather than defaulted: every listing snailmail performs is scoped
		// to a repository, and an accidental whole-bucket enumeration is expensive
		// on a bucket that is not only snailmail's.
		return ListResult{}, errors.New("a listing must be scoped to a prefix")
	}
	limit := request.Limit
	if limit <= 0 || limit > maxListPage {
		limit = maxListPage
	}
	input := &s3.ListObjectsV2Input{
		Bucket:  &client.bucket,
		Prefix:  &request.Prefix,
		MaxKeys: aws.Int32(int32(limit)),
	}
	if request.After != "" {
		input.ContinuationToken = &request.After
	}
	result, err := client.client.ListObjectsV2(ctx, input)
	if err != nil {
		return ListResult{}, normalizeAWSError(err)
	}
	objects := make([]ListedObject, 0, len(result.Contents))
	for _, object := range result.Contents {
		key := aws.ToString(object.Key)
		if key == "" {
			continue
		}
		objects = append(objects, ListedObject{
			Key: key, Size: aws.ToInt64(object.Size), ETag: aws.ToString(object.ETag),
		})
	}
	// The token is returned only when S3 says the listing was truncated, so a
	// caller looping until it is empty sees every key exactly once. Trusting
	// NextContinuationToken alone would loop forever against an implementation
	// that returns one on the final page.
	page := ListResult{Objects: objects}
	if aws.ToBool(result.IsTruncated) {
		page.More = aws.ToString(result.NextContinuationToken)
		if page.More == "" {
			return ListResult{}, errors.New("object store reported a truncated listing with no continuation token")
		}
	}
	return page, nil
}

func (client *AWSClient) Get(ctx context.Context, key string, maximum int64) ([]byte, ObjectInfo, error) {
	result, err := client.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &client.bucket, Key: &key})
	if err != nil {
		return nil, ObjectInfo{}, normalizeAWSError(err)
	}
	content, readErr := io.ReadAll(io.LimitReader(result.Body, maximum+1))
	closeErr := result.Body.Close()
	if readErr != nil {
		return nil, ObjectInfo{}, readErr
	}
	if closeErr != nil {
		return nil, ObjectInfo{}, closeErr
	}
	if int64(len(content)) > maximum {
		return nil, ObjectInfo{}, errors.New("S3 object exceeds size limit")
	}
	digest := sha256.Sum256(content)
	return content, ObjectInfo{
		ETag: aws.ToString(result.ETag), Size: aws.ToInt64(result.ContentLength),
		SHA256: hex.EncodeToString(digest[:]), Metadata: result.Metadata,
	}, nil
}

func (client *AWSClient) Put(ctx context.Context, request PutRequest) (ObjectInfo, error) {
	input := &s3.PutObjectInput{
		Bucket: &client.bucket, Key: &request.Key, Body: request.Body,
		ContentLength: &request.Size, ContentType: stringPointer(request.ContentType), Metadata: request.Metadata,
	}
	if request.SHA256 != "" {
		decoded, err := hex.DecodeString(request.SHA256)
		if err != nil {
			return ObjectInfo{}, err
		}
		input.ChecksumSHA256 = aws.String(base64.StdEncoding.EncodeToString(decoded))
	}
	if request.Conditions.IfMatch != "" {
		input.IfMatch = &request.Conditions.IfMatch
	}
	if request.Conditions.IfNoneMatch {
		value := "*"
		input.IfNoneMatch = &value
	}
	result, err := client.client.PutObject(ctx, input)
	if err != nil {
		return ObjectInfo{}, normalizeAWSError(err)
	}
	return ObjectInfo{
		ETag: aws.ToString(result.ETag), Size: request.Size,
		SHA256: hexdigest.FromBase64(aws.ToString(result.ChecksumSHA256)), Metadata: request.Metadata,
	}, nil
}

func (client *AWSClient) CopyCreate(ctx context.Context, source, destination string, expectedSize int64, expectedSHA256 string) (ObjectInfo, error) {
	sourceInfo, err := client.Head(ctx, source)
	if err != nil {
		return ObjectInfo{}, err
	}
	if sourceInfo.Size != expectedSize || sourceInfo.SHA256 != expectedSHA256 || sourceInfo.Metadata["sha256"] != expectedSHA256 {
		return ObjectInfo{}, errors.New("copy source does not match expected content")
	}
	copySource := url.PathEscape(client.bucket) + "/" + strings.ReplaceAll(url.PathEscape(source), "%2F", "/")
	ifNoneMatch := "*"
	result, err := client.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket: &client.bucket, Key: &destination, CopySource: &copySource,
		CopySourceIfMatch: &sourceInfo.ETag, IfNoneMatch: &ifNoneMatch,
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
	})
	if err != nil {
		return ObjectInfo{}, normalizeAWSError(err)
	}
	stored, err := client.Head(ctx, destination)
	if err != nil {
		return ObjectInfo{}, err
	}
	if result.CopyObjectResult != nil && result.CopyObjectResult.ETag != nil {
		stored.ETag = *result.CopyObjectResult.ETag
	}
	return stored, nil
}

func (client *AWSClient) Delete(ctx context.Context, key string, conditions Conditions) error {
	input := &s3.DeleteObjectInput{Bucket: &client.bucket, Key: &key}
	if conditions.IfMatch != "" {
		input.IfMatch = &conditions.IfMatch
	}
	_, err := client.client.DeleteObject(ctx, input)
	return normalizeAWSError(err)
}

func normalizeAWSError(err error) error {
	if err == nil {
		return nil
	}
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		switch apiError.ErrorCode() {
		case "NoSuchKey", "NotFound":
			return fmt.Errorf("%w: %v", ErrNotFound, err)
		case "NoSuchBucket":
			return err
		case "PreconditionFailed":
			return fmt.Errorf("%w: %v", ErrPrecondition, err)
		}
	}
	var responseError *transport.ResponseError
	if errors.As(err, &responseError) {
		switch responseError.HTTPStatusCode() {
		case 404:
			return fmt.Errorf("%w: %v", ErrNotFound, err)
		case 412:
			return fmt.Errorf("%w: %v", ErrPrecondition, err)
		}
	}
	return err
}

func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
