// Package auth реализует переключаемую (cookie / JWT) аутентификацию, как того
// требует раздел "План внедрения JWT" в ТЗ: cookie-сессии остаются рабочим
// режимом по умолчанию, JWT — опциональный режим (AUTH_MODE=jwt) с
// access/refresh токенами.
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 7 * 24 * time.Hour
)

type Mode string

const (
	ModeCookie Mode = "cookie"
	ModeJWT    Mode = "jwt"
)

// CurrentMode читает AUTH_MODE из окружения на каждый вызов — это позволяет
// переключать режим без пересборки, ценой одного os.Getenv на запрос.
func CurrentMode() Mode {
	if os.Getenv("AUTH_MODE") == "jwt" {
		return ModeJWT
	}
	return ModeCookie
}

// Claims — payload access-токена.
type Claims struct {
	UserID  int  `json:"uid"`
	IsAdmin bool `json:"adm"`
	jwt.RegisteredClaims
}

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

// LoadKeys загружает RS256-ключи из файлов, указанных в JWT_PRIVATE_KEY_PATH /
// JWT_PUBLIC_KEY_PATH. Если переменные не заданы, генерирует ключи в памяти —
// удобно для dev/тестов, но токены не переживут рестарт процесса и не годятся
// для нескольких инстансов за балансировщиком.
func LoadKeys() error {
	privPath := os.Getenv("JWT_PRIVATE_KEY_PATH")
	pubPath := os.Getenv("JWT_PUBLIC_KEY_PATH")
	if privPath == "" || pubPath == "" {
		log.Println("auth: JWT_PRIVATE_KEY_PATH/JWT_PUBLIC_KEY_PATH не заданы — генерирую эфемерный ключ RS256 (только для dev)")
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		privateKey = key
		publicKey = &key.PublicKey
		return nil
	}

	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(privBytes)
	if block == nil {
		return errors.New("auth: невалидный PEM в JWT_PRIVATE_KEY_PATH")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	privateKey = key

	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return err
	}
	pubBlock, _ := pem.Decode(pubBytes)
	if pubBlock == nil {
		return errors.New("auth: невалидный PEM в JWT_PUBLIC_KEY_PATH")
	}
	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("auth: JWT_PUBLIC_KEY_PATH не RSA-ключ")
	}
	publicKey = rsaPub
	return nil
}

// IssueAccessToken подписывает короткоживущий (15 мин) access-токен RS256.
func IssueAccessToken(userID int, isAdmin bool) (string, error) {
	claims := Claims{
		UserID:  userID,
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// ParseAccessToken проверяет подпись и срок действия access-токена.
func ParseAccessToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid or expired access token")
	}
	return claims, nil
}

// --- Refresh-токены: непрозрачные (opaque) случайные строки, в БД хранится
// только их SHA-256 хеш, чтобы утечка БД не давала готовые токены для угона. ---

func generateOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// IssueRefreshToken создаёт новый refresh-токен для пользователя и сохраняет
// его хеш в БД. Возвращает токен в открытом виде — единственный раз, когда он
// виден в незахешированном состоянии.
func IssueRefreshToken(db *sql.DB, userID int) (string, error) {
	token, err := generateOpaqueToken()
	if err != nil {
		return "", err
	}
	_, err = db.Exec(
		"INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
		userID, hashToken(token), time.Now().Add(RefreshTokenTTL),
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

// RotateRefreshToken проверяет переданный refresh-токен, отзывает его и сразу
// выдаёт новый тому же пользователю. Ротация при каждом обновлении означает,
// что повторное использование украденного токена детектируемо: он уже будет
// отозван к моменту повторного запроса легитимным клиентом.
func RotateRefreshToken(db *sql.DB, oldToken string) (newToken string, userID int, err error) {
	hash := hashToken(oldToken)
	var expiresAt time.Time
	var revoked bool
	err = db.QueryRow(
		"SELECT user_id, expires_at, revoked_at IS NOT NULL FROM refresh_tokens WHERE token_hash = ?",
		hash,
	).Scan(&userID, &expiresAt, &revoked)
	if err != nil {
		return "", 0, errors.New("invalid refresh token")
	}
	if revoked || time.Now().After(expiresAt) {
		return "", 0, errors.New("refresh token expired or revoked")
	}
	if _, err := db.Exec("UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = ?", hash); err != nil {
		return "", 0, err
	}
	newToken, err = IssueRefreshToken(db, userID)
	if err != nil {
		return "", 0, err
	}
	return newToken, userID, nil
}

// RevokeRefreshToken отзывает один refresh-токен (используется при logout).
func RevokeRefreshToken(db *sql.DB, token string) error {
	_, err := db.Exec(
		"UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = ? AND revoked_at IS NULL",
		hashToken(token),
	)
	return err
}

// BearerToken достаёт токен из заголовка Authorization: Bearer <token>.
func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	return strings.TrimPrefix(h, prefix), true
}
