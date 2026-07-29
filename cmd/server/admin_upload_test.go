package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func init() {
	// Best-effort: picks up local dev DB_* creds for the DB-backed subtests below.
	// Tests that need a real DB skip cleanly (via connectTestDB) when it's unavailable.
	godotenv.Load("../../.env")
}

// connectTestDB opens the dev MySQL DB and skips the test if it isn't reachable —
// this is an integration test against the real schema, not a mocked DB.
func connectTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_USER") + ":" + os.Getenv("DB_PASS") + "@tcp(" + os.Getenv("DB_HOST") + ":" + os.Getenv("DB_PORT") + ")/" + os.Getenv("DB_NAME") + "?charset=utf8mb4&parseTime=true"
	conn, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Skipf("cannot open test DB: %v", err)
	}
	if err := conn.Ping(); err != nil {
		t.Skipf("test DB not reachable, skipping integration test: %v", err)
	}
	return conn
}

func newMultipartUploadRequest(t *testing.T, token, animeID, episodeNum, title, videoPath string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("token", token)
	_ = w.WriteField("anime_id", animeID)
	_ = w.WriteField("episode_num", episodeNum)
	_ = w.WriteField("title", title)
	if videoPath != "" {
		fw, err := w.CreateFormFile("video", "input.mp4")
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(videoPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/upload-video", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

func TestAdminUploadVideoHandler_WrongToken(t *testing.T) {
	t.Setenv("ADMIN_UPLOAD_TOKEN", "correct-token")
	req := newMultipartUploadRequest(t, "wrong-token", "1", "1", "Episode 1", "")
	rec := httptest.NewRecorder()

	adminUploadVideoHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminUploadVideoHandler_TokenNotConfigured(t *testing.T) {
	t.Setenv("ADMIN_UPLOAD_TOKEN", "")
	req := newMultipartUploadRequest(t, "", "1", "1", "Episode 1", "")
	rec := httptest.NewRecorder()

	adminUploadVideoHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 when ADMIN_UPLOAD_TOKEN unset, got %d", rec.Code)
	}
}

func TestAdminUploadVideoHandler_MissingFields(t *testing.T) {
	t.Setenv("ADMIN_UPLOAD_TOKEN", "correct-token")
	req := newMultipartUploadRequest(t, "correct-token", "not-a-number", "1", "Episode 1", "")
	rec := httptest.NewRecorder()

	adminUploadVideoHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid anime_id, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminUploadVideoHandler_MissingFile(t *testing.T) {
	t.Setenv("ADMIN_UPLOAD_TOKEN", "correct-token")
	req := newMultipartUploadRequest(t, "correct-token", "1", "1", "Episode 1", "")
	rec := httptest.NewRecorder()

	adminUploadVideoHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing video file, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminUploadVideoHandler_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/admin/upload-video", nil)
	rec := httptest.NewRecorder()

	adminUploadVideoHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// TestAdminUploadVideoHandler_Success exercises the full pipeline: real ffmpeg
// transcoding + a fake S3 server standing in for MinIO + the real dev MySQL DB.
// Skips gracefully if ffmpeg or the DB aren't available locally.
func TestAdminUploadVideoHandler_Success(t *testing.T) {
	requireFFmpeg(t)
	testDB := connectTestDB(t)
	defer testDB.Close()

	fake := newFakeS3Server(t)
	client, err := minio.New(fake.endpoint(), &minio.Options{
		Creds:  credentials.NewStaticV4("test", "test", ""),
		Secure: false,
		Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}

	// Swap in the fake MinIO + test DB for the duration of this test.
	prevDB, prevClient, prevBucket, prevBaseURL := db, minioClient, minioBucket, minioPublicBaseURL
	db, minioClient, minioBucket, minioPublicBaseURL = testDB, client, "test-bucket", fake.srv.URL
	t.Cleanup(func() { db, minioClient, minioBucket, minioPublicBaseURL = prevDB, prevClient, prevBucket, prevBaseURL })

	res, err := db.Exec("INSERT INTO anime (title, description, poster_url, genres) VALUES (?, '', '', '')", "Ancen Test Anime")
	if err != nil {
		t.Fatalf("failed to insert test anime: %v", err)
	}
	animeID, _ := res.LastInsertId()
	t.Cleanup(func() {
		db.Exec("DELETE FROM episodes WHERE anime_id = ?", animeID)
		db.Exec("DELETE FROM anime WHERE id = ?", animeID)
	})

	tmpDir := t.TempDir()
	video := generateSampleVideo(t, tmpDir)

	t.Setenv("ADMIN_UPLOAD_TOKEN", "correct-token")
	req := newMultipartUploadRequest(t, "correct-token", strconv.Itoa(int(animeID)), "1", "Episode 1", video)
	rec := httptest.NewRecorder()

	adminUploadVideoHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		EpisodeID int    `json:"episode_id"`
		VideoURL  string `json:"video_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v (%s)", err, rec.Body.String())
	}
	if resp.EpisodeID == 0 {
		t.Error("expected non-zero episode_id")
	}
	if resp.VideoURL == "" {
		t.Error("expected non-empty video_url")
	}

	var videoURL string
	if err := db.QueryRow("SELECT video_url FROM episodes WHERE id = ?", resp.EpisodeID).Scan(&videoURL); err != nil {
		t.Fatalf("episode not persisted: %v", err)
	}
	if videoURL != resp.VideoURL {
		t.Errorf("DB video_url %q does not match response %q", videoURL, resp.VideoURL)
	}
}
