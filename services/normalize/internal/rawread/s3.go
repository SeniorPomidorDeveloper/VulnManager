package rawread

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"vulnmanager/modules/model"
)

type (
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	Bucket          string
)

const noSuchKey = "NoSuchKey"

var ErrNotFound = errors.New("rawread: object not found")

type S3Config struct {
	Endpoint        Endpoint
	AccessKeyID     AccessKeyID
	SecretAccessKey SecretAccessKey
	UseSSL          bool
	Bucket          Bucket
}

type S3Reader struct {
	client *minio.Client
	bucket Bucket
}

func NewS3Reader(cfg S3Config) (*S3Reader, error) {
	client, err := minio.New(string(cfg.Endpoint), &minio.Options{
		Creds:  credentials.NewStaticV4(string(cfg.AccessKeyID), string(cfg.SecretAccessKey), ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("s3 client: %w", err)
	}
	return &S3Reader{client: client, bucket: cfg.Bucket}, nil
}

func (r *S3Reader) Get(ctx context.Context, key model.RawKey) (io.ReadCloser, error) {
	object, err := r.client.GetObject(ctx, string(r.bucket), key.String(), minio.GetObjectOptions{})
	if err != nil {
		return nil, translate(err)
	}
	if _, err := object.Stat(); err != nil {
		return nil, errors.Join(translate(err), object.Close())
	}
	return object, nil
}

func translate(err error) error {
	if minio.ToErrorResponse(err).Code == noSuchKey {
		return errors.Join(ErrNotFound, err)
	}
	return fmt.Errorf("get raw object: %w", err)
}
