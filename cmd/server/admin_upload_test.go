package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func init() {
	// Best-effort: picks up local dev DB_* creds for the DB-backed subtests below.
	// Tests that need a real DB skip cleanly (via connectTestDB) when it's unavailable.
	godotenv.Load("../../.env")
	if store == nil {
		store = sessions.NewCookieStore([]byte("test-only-session-secret"))
	}
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
	ensureTestSchema(t, conn)
	return conn
}

// ensureTestSchema applies the same migrations createTables() would run at
// server startup — tests run without ever calling main(), so columns/tables
// added there (is_admin, refresh_tokens) wouldn't otherwise exist yet.
func ensureTestSchema(t *testing.T, conn *sql.DB) {
	t.Helper()
	conn.Exec("ALTER TABLE users ADD COLUMN is_admin TINYINT(1) DEFAULT 0 AFTER password_hash")
	conn.Exec(`CREATE TABLE IF NOT EXISTS refresh_tokens (
		id INT AUTO_INCREMENT PRIMARY KEY,
		user_id INT NOT NULL,
		token_hash VARCHAR(64) NOT NULL UNIQUE,
		expires_at DATETIME NOT NULL,
		revoked_at DATETIME DEFAULT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id)
	)`)
}

// createTestUser inserts a throwaway user (optionally admin) and registers cleanup.
func createTestUser(t *testing.T, testDB *sql.DB, isAdmin bool) int {
	t.Helper()
	username := fmt.Sprintf("test-admin-upload-%d", time.Now().UnixNano())
	res, err := testDB.Exec("INSERT INTO users (username, password_hash, is_admin) VALUES (?, 'x', ?)", username, isAdmin)
	if err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}
	id, _ := res.LastInsertId()
	t.Cleanup(func() { testDB.Exec("DELETE FROM users WHERE id = ?", id) })
	return int(id)
}

// cleanupRegisteredUser removes a user created through the real registerHandler
// flow, which unlocks the "early_bird" achievement (user_achievements FK) —
// deleting users first would fail the FK constraint and silently leave a stale
// row behind (Exec errors here are intentionally ignored, same as elsewhere in
// this file's cleanups).
func cleanupRegisteredUser(testDB *sql.DB, username string) {
	testDB.Exec("DELETE ua FROM user_achievements ua JOIN users u ON u.id = ua.user_id WHERE u.username = ?", username)
	testDB.Exec("DELETE FROM users WHERE username = ?", username)
}

// sessionCookie builds a valid "ancen-session" cookie for userID, the same way
// loginHandler does, so requests in tests go through the real auth path.
func sessionCookie(t *testing.T, userID int) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	session, _ := store.Get(req, "ancen-session")
	session.Values["user_id"] = userID
	if err := session.Save(req, rec); err != nil {
		t.Fatalf("failed to save session: %v", err)
	}
	res := rec.Result()
	for _, c := range res.Cookies() {
		if c.Name == "ancen-session" {
			return c
		}
	}
	t.Fatal("session cookie not set")
	return nil
}

func newMultipartUploadRequest(t *testing.T, animeID, episodeNum, title, videoPath string, authCookie *http.Cookie) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
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
	if authCookie != nil {
		req.AddCookie(authCookie)
	}
	return req
}

func TestAdminUploadVideoHandler_Unauthorized(t *testing.T) {
	req := newMultipartUploadRequest(t, "1", "1", "Episode 1", "", nil)
	rec := httptest.NewRecorder()

	adminUploadVideoHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for anonymous request, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminUploadVideoHandler_NotAdmin(t *testing.T) {
	testDB := connectTestDB(t)
	defer testDB.Close()
	prevDB := db
	db = testDB
	t.Cleanup(func() { db = prevDB })

	userID := createTestUser(t, testDB, false)
	cookie := sessionCookie(t, userID)

	req := newMultipartUploadRequest(t, "1", "1", "Episode 1", "", cookie)
	rec := httptest.NewRecorder()

	adminUploadVideoHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin user, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminUploadVideoHandler_MissingFields(t *testing.T) {
	testDB := connectTestDB(t)
	defer testDB.Close()
	prevDB := db
	db = testDB
	t.Cleanup(func() { db = prevDB })

	userID := createTestUser(t, testDB, true)
	cookie := sessionCookie(t, userID)

	req := newMultipartUploadRequest(t, "not-a-number", "1", "Episode 1", "", cookie)
	rec := httptest.NewRecorder()

	adminUploadVideoHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid anime_id, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminUploadVideoHandler_MissingFile(t *testing.T) {
	testDB := connectTestDB(t)
	defer testDB.Close()
	prevDB := db
	db = testDB
	t.Cleanup(func() { db = prevDB })

	userID := createTestUser(t, testDB, true)
	cookie := sessionCookie(t, userID)

	req := newMultipartUploadRequest(t, "1", "1", "Episode 1", "", cookie)
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
// transcoding + a fake S3 server standing in for MinIO + the real dev MySQL DB,
// authenticated as an is_admin=1 user via a real session cookie.
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

	adminID := createTestUser(t, testDB, true)
	cookie := sessionCookie(t, adminID)

	res, err := testDB.Exec("INSERT INTO anime (title, description, poster_url, genres) VALUES (?, '', '', '')", "Ancen Test Anime")
	if err != nil {
		t.Fatalf("failed to insert test anime: %v", err)
	}
	animeID, _ := res.LastInsertId()
	t.Cleanup(func() {
		testDB.Exec("DELETE FROM episodes WHERE anime_id = ?", animeID)
		testDB.Exec("DELETE FROM anime WHERE id = ?", animeID)
	})

	tmpDir := t.TempDir()
	video := generateSampleVideo(t, tmpDir)

	req := newMultipartUploadRequest(t, strconv.Itoa(int(animeID)), "1", "Episode 1", video, cookie)
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
	if err := testDB.QueryRow("SELECT video_url FROM episodes WHERE id = ?", resp.EpisodeID).Scan(&videoURL); err != nil {
		t.Fatalf("episode not persisted: %v", err)
	}
	if videoURL != resp.VideoURL {
		t.Errorf("DB video_url %q does not match response %q", videoURL, resp.VideoURL)
	}
}
