package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

func TestMain(m *testing.M) {
	if err := LoadKeys(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func TestIssueAndParseAccessToken(t *testing.T) {
	token, err := IssueAccessToken(42, true)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	claims, err := ParseAccessToken(token)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("expected UserID 42, got %d", claims.UserID)
	}
	if !claims.IsAdmin {
		t.Error("expected IsAdmin true")
	}
}

func TestParseAccessToken_Rejects(t *testing.T) {
	if _, err := ParseAccessToken("not-a-jwt"); err == nil {
		t.Error("expected error for garbage token")
	}
	if _, err := ParseAccessToken(""); err == nil {
		t.Error("expected error for empty token")
	}
}

func TestParseAccessToken_Expired(t *testing.T) {
	claims := Claims{
		UserID: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseAccessToken(signed); err == nil {
		t.Error("expected expired token to be rejected")
	}
}

func TestBearerToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer abc123")
	tok, ok := BearerToken(req)
	if !ok || tok != "abc123" {
		t.Errorf("expected abc123/true, got %q/%v", tok, ok)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := BearerToken(req2); ok {
		t.Error("expected no bearer token when header is absent")
	}

	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Header.Set("Authorization", "Basic abc123")
	if _, ok := BearerToken(req3); ok {
		t.Error("expected false for non-Bearer scheme")
	}
}

// connectTestDB opens the dev MySQL DB and skips the test if unreachable, or if
// the refresh_tokens table doesn't exist yet (created by createTables() in main).
func connectTestDB(t *testing.T) *sql.DB {
	t.Helper()
	godotenv.Load("../../.env")
	dsn := os.Getenv("DB_USER") + ":" + os.Getenv("DB_PASS") + "@tcp(" + os.Getenv("DB_HOST") + ":" + os.Getenv("DB_PORT") + ")/" + os.Getenv("DB_NAME") + "?charset=utf8mb4&parseTime=true"
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Skipf("cannot open test DB: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("test DB not reachable: %v", err)
	}
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS refresh_tokens (" +
		"id INT AUTO_INCREMENT PRIMARY KEY," +
		"user_id INT NOT NULL," +
		"token_hash VARCHAR(64) NOT NULL UNIQUE," +
		"expires_at DATETIME NOT NULL," +
		"revoked_at DATETIME DEFAULT NULL," +
		"created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"); err != nil {
		t.Skipf("cannot ensure refresh_tokens table: %v", err)
	}
	return db
}

func TestRefreshTokenLifecycle(t *testing.T) {
	db := connectTestDB(t)
	defer db.Close()

	token, err := IssueRefreshToken(db, 999999)
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	t.Cleanup(func() { db.Exec("DELETE FROM refresh_tokens WHERE user_id = ?", 999999) })

	newToken, userID, err := RotateRefreshToken(db, token)
	if err != nil {
		t.Fatalf("RotateRefreshToken: %v", err)
	}
	if userID != 999999 {
		t.Errorf("expected userID 999999, got %d", userID)
	}
	if newToken == token {
		t.Error("expected rotation to produce a different token")
	}

	// The old (rotated-out) token must now be rejected — replay detection.
	if _, _, err := RotateRefreshToken(db, token); err == nil {
		t.Error("expected rotating an already-rotated token to fail")
	}

	// The new token should work until revoked.
	if err := RevokeRefreshToken(db, newToken); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}
	if _, _, err := RotateRefreshToken(db, newToken); err == nil {
		t.Error("expected rotating a revoked token to fail")
	}
}

func TestRefreshTokenLifecycle_Expired(t *testing.T) {
	db := connectTestDB(t)
	defer db.Close()

	token, err := generateOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(
		"INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
		999998, hashToken(token), time.Now().Add(-time.Hour),
	)
	if err != nil {
		t.Fatalf("insert expired token: %v", err)
	}
	t.Cleanup(func() { db.Exec("DELETE FROM refresh_tokens WHERE user_id = ?", 999998) })

	if _, _, err := RotateRefreshToken(db, token); err == nil {
		t.Error("expected rotating an expired token to fail")
	}
}

func TestRotateRefreshToken_Unknown(t *testing.T) {
	db := connectTestDB(t)
	defer db.Close()

	if _, _, err := RotateRefreshToken(db, "does-not-exist"); err == nil {
		t.Error("expected error for unknown refresh token")
	}
}
