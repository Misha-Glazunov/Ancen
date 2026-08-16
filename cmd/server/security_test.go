package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	handler := securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("expected Content-Security-Policy header to be set")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options: nosniff")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("expected X-Frame-Options: DENY")
	}
	if rec.Header().Get("Referrer-Policy") == "" {
		t.Error("expected Referrer-Policy header to be set")
	}
}

func TestSecurityHeaders_CSPIncludesMinioHost(t *testing.T) {
	t.Setenv("MINIO_PUBLIC_BASE_URL", "http://minio.example.internal:9000")
	handler := securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "minio.example.internal:9000") {
		t.Errorf("expected CSP to include MinIO host, got: %s", csp)
	}
}

// TestSecurityHeaders_CSPAllowsBlobForVhs — регрессия на баг из сессии
// 2026-08-16: VHS-трансмаксер Video.js декодирует HLS-сегменты в веб-воркере
// и скармливает их MediaSource через blob: URL; без этих директив браузер
// тихо блокирует переключение качества в плеере.
func TestSecurityHeaders_CSPAllowsBlobForVhs(t *testing.T) {
	handler := securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "worker-src 'self' blob:") {
		t.Errorf("expected CSP to allow blob: workers, got: %s", csp)
	}
	if !strings.Contains(csp, "media-src") || !strings.Contains(csp, "blob:") {
		t.Errorf("expected media-src to allow blob:, got: %s", csp)
	}
}

func TestCsrfProtect_BlocksCrossOriginMutation(t *testing.T) {
	called := false
	handler := csrfProtect(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/comment", nil)
	req.Host = "ancen.example"
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for cross-origin POST, got %d", rec.Code)
	}
	if called {
		t.Error("handler should not have been called")
	}
}

func TestCsrfProtect_AllowsSameOriginMutation(t *testing.T) {
	called := false
	handler := csrfProtect(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/comment", nil)
	req.Host = "ancen.example"
	req.Header.Set("Origin", "https://ancen.example")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK || !called {
		t.Errorf("expected same-origin POST to pass through, got code %d called=%v", rec.Code, called)
	}
}

func TestCsrfProtect_AllowsGET(t *testing.T) {
	called := false
	handler := csrfProtect(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/comments", nil)
	req.Host = "ancen.example"
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if !called {
		t.Error("expected GET requests to bypass CSRF check regardless of Origin")
	}
}

func TestCsrfProtect_RefererFallback(t *testing.T) {
	handler := csrfProtect(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// No Origin header, mismatched Referer -> blocked.
	blocked := httptest.NewRequest(http.MethodPost, "/api/comment", nil)
	blocked.Host = "ancen.example"
	blocked.Header.Set("Referer", "https://evil.example/page")
	rec := httptest.NewRecorder()
	handler(rec, blocked)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for mismatched Referer, got %d", rec.Code)
	}

	// No Origin, matching Referer -> allowed.
	allowed := httptest.NewRequest(http.MethodPost, "/api/comment", nil)
	allowed.Host = "ancen.example"
	allowed.Header.Set("Referer", "https://ancen.example/watch?episode=1")
	rec2 := httptest.NewRecorder()
	handler(rec2, allowed)
	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200 for matching Referer, got %d", rec2.Code)
	}
}

func newMultipartFile(t *testing.T, content []byte) multipart.File {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("video", "input.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	if err := req.ParseMultipartForm(32 << 20); err != nil {
		t.Fatal(err)
	}
	f, _, err := req.FormFile("video")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSniffVideoContainer_MP4(t *testing.T) {
	// ftyp box at offset 4, as in a real MP4/MOV file.
	data := append([]byte{0x00, 0x00, 0x00, 0x18}, []byte("ftypisom")...)
	f := newMultipartFile(t, data)
	if err := sniffVideoContainer(f); err != nil {
		t.Errorf("expected MP4 signature to be recognized, got: %v", err)
	}
}

func TestSniffVideoContainer_WebM(t *testing.T) {
	data := []byte{0x1A, 0x45, 0xDF, 0xA3, 0x00, 0x00, 0x00, 0x00}
	f := newMultipartFile(t, data)
	if err := sniffVideoContainer(f); err != nil {
		t.Errorf("expected WebM/MKV signature to be recognized, got: %v", err)
	}
}

func TestSniffVideoContainer_AVI(t *testing.T) {
	data := []byte("RIFF\x00\x00\x00\x00AVI \x00\x00")
	f := newMultipartFile(t, data)
	if err := sniffVideoContainer(f); err != nil {
		t.Errorf("expected AVI signature to be recognized, got: %v", err)
	}
}

func TestSniffVideoContainer_RejectsNonVideo(t *testing.T) {
	data := []byte("<?php echo 'not a video'; ?>")
	f := newMultipartFile(t, data)
	if err := sniffVideoContainer(f); err == nil {
		t.Error("expected non-video content to be rejected")
	}
}

func TestSniffVideoContainer_RejectsTinyFile(t *testing.T) {
	f := newMultipartFile(t, []byte{0x00, 0x01})
	if err := sniffVideoContainer(f); err == nil {
		t.Error("expected too-short file to be rejected")
	}
}

func TestAdminUploadVideoHandler_RejectsNonVideoFile(t *testing.T) {
	testDB := connectTestDB(t)
	defer testDB.Close()
	prevDB := db
	db = testDB
	t.Cleanup(func() { db = prevDB })

	userID := createTestUser(t, testDB, true)
	cookie := sessionCookie(t, userID)

	tmpDir := t.TempDir()
	fakeVideo := tmpDir + "/fake.mp4"
	if err := os.WriteFile(fakeVideo, []byte("this is definitely not a video file"), 0644); err != nil {
		t.Fatal(err)
	}

	req := newMultipartUploadRequest(t, "1", "1", "Episode 1", fakeVideo, cookie)
	rec := httptest.NewRecorder()

	adminUploadVideoHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-video file content, got %d: %s", rec.Code, rec.Body.String())
	}
}
