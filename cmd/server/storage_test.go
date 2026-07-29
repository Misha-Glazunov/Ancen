package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// fakeS3Server is the minimum subset of the S3 API minio-go's FPutObject/BucketExists
// need, just enough to test uploadDir without a real MinIO instance.
type fakeS3Server struct {
	mu      sync.Mutex
	objects map[string][]byte
	srv     *httptest.Server
}

func newFakeS3Server(t *testing.T) *fakeS3Server {
	t.Helper()
	f := &fakeS3Server{objects: make(map[string][]byte)}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			// bucket-exists / head-object checks
			w.WriteHeader(http.StatusOK)
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.objects[r.URL.Path] = body
			f.mu.Unlock()
			w.Header().Set("ETag", `"fake-etag"`)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeS3Server) endpoint() string {
	return strings.TrimPrefix(f.srv.URL, "http://")
}

func (f *fakeS3Server) hasObjectSuffix(suffix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name := range f.objects {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func TestUploadDir(t *testing.T) {
	fake := newFakeS3Server(t)

	client, err := minio.New(fake.endpoint(), &minio.Options{
		Creds:  credentials.NewStaticV4("test", "test", ""),
		Secure: false,
		Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	minioClient = client
	minioBucket = "test-bucket"
	minioPublicBaseURL = fake.srv.URL

	localDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(localDir, "480p"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localDir, "master.m3u8"), []byte("#EXTM3U"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localDir, "480p", "stream.m3u8"), []byte("#EXTM3U"), 0644); err != nil {
		t.Fatal(err)
	}

	masterURL, err := uploadDir(context.Background(), localDir, "anime/1/episode/1")
	if err != nil {
		t.Fatalf("uploadDir failed: %v", err)
	}
	if !strings.HasSuffix(masterURL, "anime/1/episode/1/master.m3u8") {
		t.Errorf("unexpected master URL: %s", masterURL)
	}
	if !fake.hasObjectSuffix("anime/1/episode/1/master.m3u8") {
		t.Error("master.m3u8 was not uploaded")
	}
	if !fake.hasObjectSuffix("anime/1/episode/1/480p/stream.m3u8") {
		t.Error("rendition playlist was not uploaded")
	}
}

func TestUploadDirMissingMaster(t *testing.T) {
	fake := newFakeS3Server(t)
	client, err := minio.New(fake.endpoint(), &minio.Options{
		Creds:  credentials.NewStaticV4("test", "test", ""),
		Secure: false,
		Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	minioClient = client
	minioBucket = "test-bucket"
	minioPublicBaseURL = fake.srv.URL

	localDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(localDir, "note.txt"), []byte("no master here"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := uploadDir(context.Background(), localDir, "anime/1/episode/2"); err == nil {
		t.Error("expected error when master.m3u8 is missing, got nil")
	}
}
