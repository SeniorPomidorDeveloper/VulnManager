package rawstore

import (
	"context"
	"errors"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type S3Config struct {
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	UseSSL          bool
	Bucket          string
}

type S3Store struct {
	client *minio.Client
	bucket string
}

func NewS3Store(cfg S3Config) (*S3Store, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, err
	}
	return &S3Store{client: client, bucket: cfg.Bucket}, nil
}

func (s *S3Store) Put(ctx context.Context, key Key, r io.Reader, size int64) error {
	_, err := s.client.PutObject(ctx, s.bucket, key.String(), r, size, minio.PutObjectOptions{})
	return err
}

func (s *S3Store) Get(ctx context.Context, key Key) (io.ReadCloser, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key.String(), minio.GetObjectOptions{})
	if err != nil {
		return nil, translateS3Error(err)
	}
	if _, err := obj.Stat(); err != nil {
		_ = obj.Close()
		return nil, translateS3Error(err)
	}
	return obj, nil
}

func (s *S3Store) Stat(ctx context.Context, key Key) (Info, error) {
	info, err := s.client.StatObject(ctx, s.bucket, key.String(), minio.StatObjectOptions{})
	if err != nil {
		return Info{}, translateS3Error(err)
	}
	return Info{Size: info.Size}, nil
}

func translateS3Error(err error) error {
	resp := minio.ToErrorResponse(err)
	if resp.Code == "NoSuchKey" {
		return errors.Join(ErrNotFound, err)
	}
	return err
}
