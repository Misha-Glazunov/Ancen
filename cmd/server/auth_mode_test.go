package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"Ancen/internal/auth"
)

func init() {
	if err := auth.LoadKeys(); err != nil {
		panic(err)
	}
}

func TestBcryptCostIs12(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("some-password"), bcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	cost, err := bcrypt.Cost(hash)
	if err != nil {
		t.Fatal(err)
	}
	if cost != 12 {
		t.Errorf("expected bcrypt cost 12, got %d", cost)
	}
}

func TestGetUserIDFromSession_CookieMode(t *testing.T) {
	t.Setenv("AUTH_MODE", "cookie")
	if store == nil {
		t.Fatal("store not initialized")
	}

	cookie := sessionCookie(t, 123)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	userID, err := getUserIDFromSession(req)
	if err != nil {
		t.Fatalf("getUserIDFromSession: %v", err)
	}
	if userID != 123 {
		t.Errorf("expected userID 123, got %d", userID)
	}
}

func TestGetUserIDFromSession_CookieMode_NoCookie(t *testing.T) {
	t.Setenv("AUTH_MODE", "cookie")
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if _, err := getUserIDFromSession(req); err == nil {
		t.Error("expected error for request without session cookie")
	}
}

func TestGetUserIDFromSession_JWTMode_BearerHeader(t *testing.T) {
	t.Setenv("AUTH_MODE", "jwt")

	token, err := auth.IssueAccessToken(77, false)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	userID, err := getUserIDFromSession(req)
	if err != nil {
		t.Fatalf("getUserIDFromSession: %v", err)
	}
	if userID != 77 {
		t.Errorf("expected userID 77, got %d", userID)
	}
}

func TestGetUserIDFromSession_JWTMode_CookieFallback(t *testing.T) {
	t.Setenv("AUTH_MODE", "jwt")

	token, err := auth.IssueAccessToken(88, false)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	userID, err := getUserIDFromSession(req)
	if err != nil {
		t.Fatalf("getUserIDFromSession: %v", err)
	}
	if userID != 88 {
		t.Errorf("expected userID 88, got %d", userID)
	}
}

func TestGetUserIDFromSession_JWTMode_NoToken(t *testing.T) {
	t.Setenv("AUTH_MODE", "jwt")
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if _, err := getUserIDFromSession(req); err == nil {
		t.Error("expected error for request without access token")
	}
}

func TestIsUserAdmin(t *testing.T) {
	testDB := connectTestDB(t)
	defer testDB.Close()
	prevDB := db
	db = testDB
	t.Cleanup(func() { db = prevDB })

	adminID := createTestUser(t, testDB, true)
	regularID := createTestUser(t, testDB, false)

	if !isUserAdmin(adminID) {
		t.Error("expected admin user to be recognized as admin")
	}
	if isUserAdmin(regularID) {
		t.Error("expected regular user to not be admin")
	}
	if isUserAdmin(-1) {
		t.Error("expected unknown user id to not be admin")
	}
}

func TestApiAuthRefreshAndLogout_Roundtrip(t *testing.T) {
	testDB := connectTestDB(t)
	defer testDB.Close()
	prevDB := db
	db = testDB
	t.Cleanup(func() { db = prevDB })
	t.Setenv("AUTH_MODE", "jwt")

	userID := createTestUser(t, testDB, false)

	refreshToken, err := auth.IssueRefreshToken(testDB, userID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testDB.Exec("DELETE FROM refresh_tokens WHERE user_id = ?", userID) })

	// /api/auth/refresh should rotate the token and set fresh cookies.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
	rec := httptest.NewRecorder()

	apiAuthRefreshHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var newRefresh, newAccess string
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case "refresh_token":
			newRefresh = c.Value
		case "access_token":
			newAccess = c.Value
		}
	}
	if newRefresh == "" || newAccess == "" {
		t.Fatal("expected refresh handler to set both cookies")
	}
	if newRefresh == refreshToken {
		t.Error("expected refresh token rotation to produce a new token")
	}

	// The old refresh token must now be rejected (replay protection).
	replayReq := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	replayReq.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
	replayRec := httptest.NewRecorder()
	apiAuthRefreshHandler(replayRec, replayReq)
	if replayRec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 replaying a rotated-out refresh token, got %d", replayRec.Code)
	}

	// /api/auth/logout revokes the current refresh token and clears cookies.
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	logoutReq.AddCookie(&http.Cookie{Name: "refresh_token", Value: newRefresh})
	logoutRec := httptest.NewRecorder()
	apiAuthLogoutHandler(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from logout, got %d", logoutRec.Code)
	}

	postLogoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	postLogoutReq.AddCookie(&http.Cookie{Name: "refresh_token", Value: newRefresh})
	postLogoutRec := httptest.NewRecorder()
	apiAuthRefreshHandler(postLogoutRec, postLogoutReq)
	if postLogoutRec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 refreshing a revoked (logged-out) token, got %d", postLogoutRec.Code)
	}
}

func TestApiAuthRefreshHandler_RequiresJWTMode(t *testing.T) {
	t.Setenv("AUTH_MODE", "cookie")
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	rec := httptest.NewRecorder()

	apiAuthRefreshHandler(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("expected 501 in cookie mode, got %d", rec.Code)
	}
}

func TestStartAuthSession_JWTMode_SetsCookies(t *testing.T) {
	testDB := connectTestDB(t)
	defer testDB.Close()
	prevDB := db
	db = testDB
	t.Cleanup(func() { db = prevDB })
	t.Setenv("AUTH_MODE", "jwt")

	userID := createTestUser(t, testDB, false)
	t.Cleanup(func() { testDB.Exec("DELETE FROM refresh_tokens WHERE user_id = ?", userID) })

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rec := httptest.NewRecorder()

	if err := startAuthSession(rec, req, userID, "someone"); err != nil {
		t.Fatalf("startAuthSession: %v", err)
	}

	var hasAccess, hasRefresh bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "access_token" {
			hasAccess = true
		}
		if c.Name == "refresh_token" {
			hasRefresh = true
		}
	}
	if !hasAccess || !hasRefresh {
		t.Errorf("expected both access_token and refresh_token cookies, got access=%v refresh=%v", hasAccess, hasRefresh)
	}
}
