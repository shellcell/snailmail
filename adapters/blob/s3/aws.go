package s3blob

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	transport "github.com/aws/smithy-go/transport/http"
	"github.com/shellcell/snailmail/blob"
)

type AWSClient struct {
	client *s3.Client
	bucket string
}

func NewAWS(ctx context.Context, configuration blob.Configuration) (*Store, error) {
	if configuration.Type != "s3" || configuration.Bucket == "" {
		return nil, errors.New("S3 blob bucket is required")
	}
	if err := validateAWSEndpoint(configuration.Endpoint); err != nil {
		return nil, err
	}
	options := []func(*awsconfig.LoadOptions) error{}
	if configuration.Region != "" {
		options = append(options, awsconfig.WithRegion(configuration.Region))
	}
	loaded, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	client := s3.NewFromConfig(loaded, func(options *s3.Options) {
		options.UsePathStyle = configuration.UsePathStyle
		if configuration.Endpoint != "" {
			options.BaseEndpoint = aws.String(configuration.Endpoint)
		}
	})
	return New(&AWSClient{client: client, bucket: configuration.Bucket}, configuration)
}

func validateAWSEndpoint(value string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return errors.New("invalid S3 blob endpoint")
	}
	loopback := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1"
	if parsed.Scheme != "https" && !loopback {
		return errors.New("S3 blob endpoint must use HTTPS")
	}
	return nil
}

func (client *AWSClient) Head(ctx context.Context, key string) (ObjectInfo, error) {
	result, err := client.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &client.bucket, Key: &key, ChecksumMode: types.ChecksumModeEnabled})
	if err != nil {
		return ObjectInfo{}, normalizeAWSError(err)
	}
	return ObjectInfo{Size: aws.ToInt64(result.ContentLength), SHA256: decodeChecksum(aws.ToString(result.ChecksumSHA256)), Metadata: result.Metadata}, nil
}

func (client *AWSClient) PutCreate(ctx context.Context, key string, body io.Reader, size int64, sha256Value string, metadata map[string]string) (ObjectInfo, error) {
	decoded, err := hex.DecodeString(sha256Value)
	if err != nil {
		return ObjectInfo{}, err
	}
	ifNoneMatch := "*"
	result, err := client.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &client.bucket, Key: &key, Body: body, ContentLength: &size,
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(decoded)), Metadata: metadata, IfNoneMatch: &ifNoneMatch,
	})
	if err != nil {
		return ObjectInfo{}, normalizeAWSError(err)
	}
	return ObjectInfo{Size: size, SHA256: decodeChecksum(aws.ToString(result.ChecksumSHA256)), Metadata: metadata}, nil
}

func (client *AWSClient) Get(ctx context.Context, key string) (io.ReadCloser, ObjectInfo, error) {
	result, err := client.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &client.bucket, Key: &key, ChecksumMode: types.ChecksumModeEnabled})
	if err != nil {
		return nil, ObjectInfo{}, normalizeAWSError(err)
	}
	return result.Body, ObjectInfo{Size: aws.ToInt64(result.ContentLength), SHA256: decodeChecksum(aws.ToString(result.ChecksumSHA256)), Metadata: result.Metadata}, nil
}

func normalizeAWSError(err error) error {
	if err == nil {
		return nil
	}
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		switch apiError.ErrorCode() {
		case "NoSuchKey", "NotFound":
			return fmt.Errorf("%w: %v", blob.ErrNotFound, err)
		case "NoSuchBucket":
			return err
		case "PreconditionFailed":
			return fmt.Errorf("%w: %v", blob.ErrPrecondition, err)
		}
	}
	var responseError *transport.ResponseError
	if errors.As(err, &responseError) {
		switch responseError.HTTPStatusCode() {
		case 412:
			return fmt.Errorf("%w: %v", blob.ErrPrecondition, err)
		}
	}
	return err
}

func decodeChecksum(value string) string {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(decoded)
}
