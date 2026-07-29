package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestDeleteUserData_RemovesUserAndRelatedRows(t *testing.T) {
	testDB := connectTestDB(t)
	defer testDB.Close()
	prevDB := db
	db = testDB
	t.Cleanup(func() { db = prevDB })

	userID := createTestUser(t, testDB, false)

	// Seed rows in every table deleteUserData is supposed to clean up.
	res, err := testDB.Exec("INSERT INTO anime (title, description, poster_url, genres) VALUES ('t','','','')")
	if err != nil {
		t.Fatal(err)
	}
	animeID, _ := res.LastInsertId()
	epRes, err := testDB.Exec("INSERT INTO episodes (anime_id, episode_num, title, video_url) VALUES (?, 1, 'ep', 'http://x')", animeID)
	if err != nil {
		t.Fatal(err)
	}
	episodeID, _ := epRes.LastInsertId()
	t.Cleanup(func() {
		testDB.Exec("DELETE FROM episodes WHERE anime_id = ?", animeID)
		testDB.Exec("DELETE FROM anime WHERE id = ?", animeID)
	})

	testDB.Exec("INSERT INTO emotions (user_id, episode_id, timestamp_sec, emotion_type) VALUES (?, ?, 1, '🔥')", userID, episodeID)
	testDB.Exec("INSERT INTO comments (user_id, episode_id, timestamp_sec, text) VALUES (?, ?, 1, 'hi')", userID, episodeID)
	testDB.Exec("INSERT INTO user_xp (user_id, xp) VALUES (?, 10)", userID)
	testDB.Exec("INSERT INTO user_progress (user_id, episode_id, last_timestamp_sec) VALUES (?, ?, 5)", userID, episodeID)

	if err := deleteUserData(userID); err != nil {
		t.Fatalf("deleteUserData: %v", err)
	}

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count)
	if count != 0 {
		t.Error("expected user row to be deleted")
	}
	testDB.QueryRow("SELECT COUNT(*) FROM emotions WHERE user_id = ?", userID).Scan(&count)
	if count != 0 {
		t.Error("expected emotions to be deleted")
	}
	testDB.QueryRow("SELECT COUNT(*) FROM comments WHERE user_id = ?", userID).Scan(&count)
	if count != 0 {
		t.Error("expected comments to be deleted")
	}
	testDB.QueryRow("SELECT COUNT(*) FROM user_xp WHERE user_id = ?", userID).Scan(&count)
	if count != 0 {
		t.Error("expected user_xp to be deleted")
	}
	testDB.QueryRow("SELECT COUNT(*) FROM user_progress WHERE user_id = ?", userID).Scan(&count)
	if count != 0 {
		t.Error("expected user_progress to be deleted")
	}
}

func TestApiUserDeleteHandler_WrongPassword(t *testing.T) {
	testDB := connectTestDB(t)
	defer testDB.Close()
	prevDB := db
	db = testDB
	t.Cleanup(func() { db = prevDB })

	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	username := fmt.Sprintf("delete-test-user-%d", time.Now().UnixNano())
	res, err := testDB.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, string(hash))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	t.Cleanup(func() { testDB.Exec("DELETE FROM users WHERE id = ?", id) })
	cookie := sessionCookie(t, int(id))

	body, _ := json.Marshal(map[string]string{"password": "wrong-password"})
	req := httptest.NewRequest(http.MethodPost, "/api/user/delete", bytes.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	apiUserDeleteHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong password, got %d: %s", rec.Code, rec.Body.String())
	}

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", id).Scan(&count)
	if count != 1 {
		t.Error("expected user to still exist after failed delete attempt")
	}
}

func TestApiUserDeleteHandler_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/user/delete", bytes.NewReader([]byte(`{"password":"x"}`)))
	rec := httptest.NewRecorder()

	apiUserDeleteHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for anonymous request, got %d", rec.Code)
	}
}

func TestApiUserDeleteHandler_Success(t *testing.T) {
	testDB := connectTestDB(t)
	defer testDB.Close()
	prevDB := db
	db = testDB
	t.Cleanup(func() { db = prevDB })

	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	username := fmt.Sprintf("delete-test-user-success-%d", time.Now().UnixNano())
	res, err := testDB.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, string(hash))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	t.Cleanup(func() { testDB.Exec("DELETE FROM users WHERE id = ?", id) })
	cookie := sessionCookie(t, int(id))

	body, _ := json.Marshal(map[string]string{"password": "correct-password"})
	req := httptest.NewRequest(http.MethodPost, "/api/user/delete", bytes.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	apiUserDeleteHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", id).Scan(&count)
	if count != 0 {
		t.Error("expected user to be deleted")
	}
}

func TestRegisterHandler_StoresEncryptedEmail(t *testing.T) {
	testDB := connectTestDB(t)
	defer testDB.Close()
	prevDB := db
	db = testDB
	t.Cleanup(func() { db = prevDB })

	username := fmt.Sprintf("encrypt-test-user-%d", time.Now().UnixNano())
	form := fmt.Sprintf("username=%s&password=password123&email=secret@example.com&consent=1", username)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	registerHandler(rec, req)
	t.Cleanup(func() { cleanupRegisteredUser(testDB, username) })

	var storedEmail string
	if err := testDB.QueryRow("SELECT email FROM users WHERE username = ?", username).Scan(&storedEmail); err != nil {
		t.Fatalf("user not created: %v", err)
	}
	if storedEmail == "secret@example.com" {
		t.Error("expected email to be stored encrypted, found plaintext")
	}
	if storedEmail == "" {
		t.Fatal("expected non-empty encrypted email")
	}

	decrypted, err := decryptEmail(storedEmail)
	if err != nil {
		t.Fatalf("decryptEmail: %v", err)
	}
	if decrypted != "secret@example.com" {
		t.Errorf("expected decrypted email to round-trip, got %q", decrypted)
	}
}

func TestRegisterHandler_RequiresConsent(t *testing.T) {
	testDB := connectTestDB(t)
	defer testDB.Close()
	prevDB := db
	db = testDB
	t.Cleanup(func() { db = prevDB })

	username := fmt.Sprintf("no-consent-user-%d", time.Now().UnixNano())
	form := fmt.Sprintf("username=%s&password=password123", username)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	registerHandler(rec, req)
	t.Cleanup(func() { cleanupRegisteredUser(testDB, username) })

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if count != 0 {
		t.Error("expected registration without consent to be rejected")
	}
}
