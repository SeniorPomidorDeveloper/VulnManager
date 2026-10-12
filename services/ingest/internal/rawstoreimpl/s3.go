package rawstoreimpl

import (
	"context"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"vulnmanager/modules/model"
)

type S3Config struct {
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	UseSSL          bool
	Bucket          string
}

type S3Writer struct {
	client *minio.Client
	bucket string
}

func NewS3Writer(cfg S3Config) (*S3Writer, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, err
	}
	return &S3Writer{client: client, bucket: cfg.Bucket}, nil
}

func (s *S3Writer) Put(ctx context.Context, key model.RawKey, r io.Reader, size int64) error {
	_, err := s.client.PutObject(ctx, s.bucket, key.String(), r, size, minio.PutObjectOptions{})
	return err
}
