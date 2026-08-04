package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var minioClient *minio.Client
var minioBucket string
var minioPublicBaseURL string

func initMinioClient() {
	minioBucket = os.Getenv("MINIO_BUCKET")
	minioPublicBaseURL = strings.TrimRight(os.Getenv("MINIO_PUBLIC_BASE_URL"), "/")

	client, err := minio.New(os.Getenv("MINIO_ENDPOINT"), &minio.Options{
		Creds:  credentials.NewStaticV4(os.Getenv("MINIO_ACCESS_KEY"), os.Getenv("MINIO_SECRET_KEY"), ""),
		Secure: false,
	})
	if err != nil {
		log.Println("MinIO init error:", err)
		return
	}
	minioClient = client

	ctx := context.Background()
	exists, err := client.BucketExists(ctx, minioBucket)
	if err != nil {
		log.Println("MinIO bucket check error:", err)
		return
	}
	if !exists {
		if err := client.MakeBucket(ctx, minioBucket, minio.MakeBucketOptions{}); err != nil {
			log.Println("MinIO create bucket error:", err)
			return
		}
	}

	// Видео не приватные данные — раздаём объекты напрямую по URL без presigned-подписи,
	// иначе пришлось бы подписывать каждый .ts-сегмент HLS-плейлиста отдельно.
	policy := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": ["*"]},
			"Action": ["s3:GetObject"],
			"Resource": ["arn:aws:s3:::%s/*"]
		}]
	}`, minioBucket)
	if err := client.SetBucketPolicy(ctx, minioBucket, policy); err != nil {
		log.Println("MinIO set bucket policy error:", err)
	}
}

// uploadDir заливает все файлы из localDir в MinIO под objectPrefix, сохраняя
// относительную структуру папок (нужно для HLS: master.m3u8 + <rendition>/stream.m3u8 + сегменты).
// Возвращает публичный URL мастер-плейлиста.
func uploadDir(ctx context.Context, localDir, objectPrefix string) (string, error) {
	var masterURL string
	err := filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(localDir, path)
		if err != nil {
			return err
		}
		objectName := objectPrefix + "/" + filepath.ToSlash(rel)
		if _, err := minioClient.FPutObject(ctx, minioBucket, objectName, path, minio.PutObjectOptions{}); err != nil {
			return err
		}
		if rel == "master.m3u8" {
			masterURL = fmt.Sprintf("%s/%s/%s", minioPublicBaseURL, minioBucket, objectName)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if masterURL == "" {
		return "", fmt.Errorf("master.m3u8 не найден в %s после транскода", localDir)
	}
	return masterURL, nil
}

// uploadSingleFile заливает один файл (например, аватар) в MinIO под заданным именем
// объекта и возвращает публичный URL. В отличие от uploadDir — без обхода директории,
// для одиночных небольших файлов.
func uploadSingleFile(ctx context.Context, localPath, objectName, contentType string) (string, error) {
	_, err := minioClient.FPutObject(ctx, minioBucket, objectName, localPath, minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s/%s", minioPublicBaseURL, minioBucket, objectName), nil
}
