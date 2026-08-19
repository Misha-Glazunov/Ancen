package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"image"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp"

	"Ancen/internal/auth"
)

// bcryptCost — ТЗ требует cost=12 (сильнее дефолтного cost=10 из golang.org/x/crypto).
const bcryptCost = 12

// Глобальные переменные
var db *sql.DB
var templates *template.Template
var store *sessions.CookieStore

// maintenanceMode — кэш флага "сайт на техработах" из app_settings, чтобы не
// ходить в БД на каждый запрос. Обновляется через apiAdminMaintenanceToggle.
// ponytail: atomic.Bool не переживёт несколько инстансов сервера за балансировщиком —
// при горизонтальном масштабировании читать флаг из БД/Redis вместо памяти процесса.
var maintenanceMode atomic.Bool

// ---------- Защита от подбора пароля (brute-force) ----------

const (
	maxLoginAttempts  = 5
	loginLockDuration = 15 * time.Minute
)

type loginAttemptInfo struct {
	failedCount int
	lockedUntil time.Time
}

var (
	loginAttemptsMu sync.Mutex
	loginAttempts   = make(map[string]*loginAttemptInfo)
)

// clientIP извлекает IP клиента из запроса (без учёта X-Forwarded-For, чтобы его нельзя было подделать)
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}

// loginRateLimitKey — ключ лимитера: логин + IP, чтобы блокировка была привязана и к конкретному
// аккаунту (защита жертвы), и к источнику (защита от перебора по многим логинам с одного IP)
func loginRateLimitKey(username, ip string) string {
	return strings.ToLower(username) + "|" + ip
}

// isLoginLocked проверяет, заблокирован ли вход для данной пары логин+IP
func isLoginLocked(username, ip string) (bool, time.Duration) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	info, ok := loginAttempts[loginRateLimitKey(username, ip)]
	if !ok {
		return false, 0
	}
	if time.Now().Before(info.lockedUntil) {
		return true, time.Until(info.lockedUntil)
	}
	return false, 0
}

// registerFailedLogin увеличивает счётчик неудачных попыток и блокирует при превышении лимита
func registerFailedLogin(username, ip string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	key := loginRateLimitKey(username, ip)
	info, ok := loginAttempts[key]
	if !ok {
		info = &loginAttemptInfo{}
		loginAttempts[key] = info
	}
	info.failedCount++
	if info.failedCount >= maxLoginAttempts {
		info.lockedUntil = time.Now().Add(loginLockDuration)
		info.failedCount = 0
	}
}

// resetLoginAttempts сбрасывает счётчик после успешного входа
func resetLoginAttempts(username, ip string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	delete(loginAttempts, loginRateLimitKey(username, ip))
}

// ---------- Анти-спам: реакции и комментарии ----------

const (
	emotionRateLimit  = 10
	emotionRateWindow = 10 * time.Second
	commentRateLimit  = 5
	commentRateWindow = 30 * time.Second
	messageRateLimit  = 10
	messageRateWindow = 30 * time.Second

	registerRateLimit  = 5
	registerRateWindow = time.Hour

	forgotPasswordRateLimit  = 3
	forgotPasswordRateWindow = time.Hour
)

// emotionPreset — тип реакции. Базовые (MinLevel 1) доступны всем, эксклюзивные
// анимированные (Animated true) разблокируются уровнем — та же бесплатная
// косметика за активность, что рамки аватара/цвет графика, см. 18_Монетизация_и_уровни.md.
type emotionPreset struct {
	Emoji    string
	MinLevel int
	Animated bool
}

var emotionPresets = []emotionPreset{
	{Emoji: "❤️", MinLevel: 1},
	{Emoji: "😭", MinLevel: 1},
	{Emoji: "🔥", MinLevel: 1},
	{Emoji: "🤯", MinLevel: 1},
	{Emoji: "🥰", MinLevel: 1},
	{Emoji: "😂", MinLevel: 1},
	{Emoji: "👍", MinLevel: 1},
	{Emoji: "💢", MinLevel: 1},
	{Emoji: "✨", MinLevel: 6, Animated: true},
	{Emoji: "💯", MinLevel: 9, Animated: true},
	{Emoji: "👑", MinLevel: 12, Animated: true},
}

func emotionPresetByEmoji(emoji string) (emotionPreset, bool) {
	for _, p := range emotionPresets {
		if p.Emoji == emoji {
			return p, true
		}
	}
	return emotionPreset{}, false
}

var validEmotions = func() map[string]bool {
	m := make(map[string]bool, len(emotionPresets))
	for _, p := range emotionPresets {
		m[p.Emoji] = true
	}
	return m
}()

// userLevel возвращает текущий уровень пользователя по его XP.
func userLevel(userID int) int {
	var xp int
	db.QueryRow("SELECT xp FROM user_xp WHERE user_id = ?", userID).Scan(&xp)
	return getLevelInfo(xp).Level
}

type actionRateLimiter struct {
	mu     sync.Mutex
	events map[string][]time.Time
}

var actionLimiter = &actionRateLimiter{events: make(map[string][]time.Time)}

// allow возвращает true, если действие (реакция/комментарий) укладывается в лимит
// по скользящему окну для данного ключа (userID+вид действия)
func (l *actionRateLimiter) allow(key string, limit int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-window)
	kept := l.events[key][:0]
	for _, t := range l.events[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		l.events[key] = kept
		return false
	}
	l.events[key] = append(kept, now)
	return true
}

// ---------- Анти-спойлер: реакции/комментарии видны только premium-пользователям целиком ----------

func isPremiumUser(userID int) bool {
	if userID <= 0 {
		return false
	}
	var isPremium bool
	var premiumUntil sql.NullTime
	db.QueryRow("SELECT is_premium, premium_until FROM users WHERE id = ?", userID).Scan(&isPremium, &premiumUntil)
	if !isPremium {
		return false
	}
	// premium_until = NULL — бессрочный Premium (включён вручную SQL/админкой).
	// Задан и уже прошёл — срок вышел (например, награда за ретеншн истекла);
	// самоочищаем флаг здесь же, чтобы админка и остальной код не путались.
	if premiumUntil.Valid && premiumUntil.Time.Before(time.Now()) {
		db.Exec("UPDATE users SET is_premium = 0, premium_until = NULL WHERE id = ?", userID)
		return false
	}
	return true
}

// watchedUpToSec — источник истины для "докуда пользователь досмотрел серию": берём
// сохранённый прогресс просмотра (user_progress, пишется /api/progress раз в 5с плеером),
// а не значение из query-параметра запроса — иначе клиент мог бы просто прислать
// произвольный таймкод и увидеть все реакции/комментарии без подписки
func watchedUpToSec(userID, episodeID int) int {
	if userID <= 0 {
		return 0
	}
	var sec int
	db.QueryRow("SELECT last_timestamp_sec FROM user_progress WHERE user_id = ? AND episode_id = ?", userID, episodeID).Scan(&sec)
	return sec
}

// ---------- Мидлвары безопасности ----------

// securityHeaders выставляет заголовки, снижающие ущерб от XSS/clickjacking/
// MIME-sniffing. CSP разрешает 'unsafe-inline' для script-src/style-src —
// ponytail: шаблоны используют инлайн-скрипты и стили (watch.html и др.),
// переход на nonce-based CSP потребует переписать фронтенд, это отдельная
// задача. connect-src/media-src подключают MinIO по MINIO_PUBLIC_BASE_URL,
// чтобы видео/HLS-сегменты вообще грузились под CSP.
func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mediaSrc := "'self'"
		if base := os.Getenv("MINIO_PUBLIC_BASE_URL"); base != "" {
			if u, err := url.Parse(base); err == nil && u.Host != "" {
				mediaSrc += " " + u.Scheme + "://" + u.Host
			}
		}
		csp := strings.Join([]string{
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline' https://vjs.zencdn.net https://cdnjs.cloudflare.com",
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://vjs.zencdn.net",
			"font-src 'self' https://fonts.gstatic.com data:",
			"img-src 'self' data: https: " + mediaSrc,
			// blob: нужен трансмаксеру VHS (Video.js) — он декодирует HLS-сегменты
			// в веб-воркере и скармливает их MediaSource через blob: URL.
			"media-src " + mediaSrc + " https://vjs.zencdn.net blob:",
			"worker-src 'self' blob:",
			"connect-src 'self' ws: wss: " + mediaSrc,
			"frame-ancestors 'none'",
			"base-uri 'self'",
			"form-action 'self'",
		}, "; ")
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next(w, r)
	}
}

// csrfProtect проверяет Origin (с фолбэком на Referer, если Origin отсутствует)
// для мутирующих методов — вторая линия защиты от CSRF поверх SameSite=Strict
// на сессионной cookie. Запросы вообще без Origin и Referer (curl, серверные
// клиенты) пропускаются — как и в sameOrigin для WS.
func csrfProtect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			checkURL := r.Header.Get("Origin")
			if checkURL == "" {
				checkURL = r.Header.Get("Referer")
			}
			if checkURL != "" {
				u, err := url.Parse(checkURL)
				if err != nil || u.Host != r.Host {
					http.Error(w, `{"error":"CSRF check failed"}`, http.StatusForbidden)
					return
				}
			}
		}
		next(w, r)
	}
}

// secureHandle регистрирует хендлер с обеими мидлварами безопасности — все
// маршруты в main() должны идти через неё вместо голого http.HandleFunc.
func secureHandle(pattern string, h http.HandlerFunc) {
	handler := securityHeaders(csrfProtect(h))
	if shouldGateMaintenance(pattern) {
		handler = maintenanceGate(handler)
	}
	if shouldTrackVisit(pattern) {
		handler = trackVisit(handler)
	}
	http.HandleFunc(pattern, handler)
}

// shouldGateMaintenance исключает /admin* и /login|/register|/logout из
// проверки техработ — иначе админ не смог бы зайти и выключить maintenance mode.
func shouldGateMaintenance(pattern string) bool {
	if strings.HasPrefix(pattern, "/admin") || strings.HasPrefix(pattern, "/api/admin") {
		return false
	}
	switch pattern {
	case "/login", "/register", "/logout":
		return false
	}
	return true
}

const maintenancePageHTML = `<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Технические работы — AniMemory</title></head>
<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f0f0f;color:#fff;font-family:sans-serif;text-align:center;padding:20px;">
<div><h1 style="font-size:22px;margin-bottom:8px;">Сайт на техническом обслуживании</h1><p style="color:#adadad;">Мы скоро вернёмся. Попробуйте зайти чуть позже.</p></div>
</body></html>`

// maintenanceGate закрывает публичные маршруты, если включён maintenance mode
// (/admin/settings), пропуская только залогиненных администраторов.
func maintenanceGate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if maintenanceMode.Load() {
			if uid, err := getUserIDFromSession(r); err != nil || !isUserAdmin(uid) {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(maintenancePageHTML))
				return
			}
		}
		next(w, r)
	}
}

// shouldTrackVisit исключает API/WS/служебные маршруты из лога визитов
// (admin_visits) — там считаем только реальные переходы по страницам.
func shouldTrackVisit(pattern string) bool {
	switch pattern {
	case "/ws", "/robots.txt", "/sitemap.xml":
		return false
	}
	return !strings.HasPrefix(pattern, "/api/")
}

// trackVisit пишет строку в admin_visits для графиков /admin (визиты,
// сессии, устройства). Запись — в фоне, не блокирует ответ.
func trackVisit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// getUserIDFromSession трогает gorilla/sessions, которое хранит
			// служебные данные по ключу *http.Request — читать это из отдельной
			// горутины, пока тот же r обрабатывается хендлером next(), приводило
			// к concurrent map writes и падению сервера. Читаем синхронно здесь,
			// в горутину уходят только простые значения.
			var userID interface{}
			if uid, err := getUserIDFromSession(r); err == nil && uid != 0 {
				userID = uid
			}
			cookie, cookieErr := r.Cookie("ancen-session")
			path, ua := r.URL.Path, r.UserAgent()
			if cookieErr == nil && cookie.Value != "" {
				go logVisit(userID, cookie.Value, path, ua)
			}
		}
		next(w, r)
	}
}

// logVisit требует cookie сессии — гость без ранее выданной cookie (первый
// запрос до session.Save()) в текущей итерации не логируется.
// ponytail: не 100% охват гостевого трафика, добавить принудительный
// session.Save() на первом запросе, если это станет важно.
func logVisit(userID interface{}, cookieValue, path, userAgent string) {
	if db == nil {
		return
	}
	sum := sha256.Sum256([]byte(cookieValue))
	sessionID := hex.EncodeToString(sum[:])

	device := "desktop"
	if strings.Contains(userAgent, "Mobi") {
		device = "mobile"
	}

	db.Exec("INSERT INTO admin_visits (user_id, session_id, path, device) VALUES (?,?,?,?)",
		userID, sessionID, path, device)

	// Ретеншн-механика: считаем день активным для залогиненного пользователя
	// (INSERT IGNORE — идемпотентно, повторные визиты в тот же день не в счёт),
	// и заодно проверяем, не пора ли выдать награду.
	if uid, ok := userID.(int); ok && uid > 0 {
		db.Exec("INSERT IGNORE INTO user_daily_visits (user_id, day) VALUES (?, CURDATE())", uid)
		checkRetentionReward(uid)
	}
}

// PageData используется для передачи данных в шаблоны
type PageData struct {
	Title    string
	Error    string
	Success  string
	Username string
}

// Инициализация: загружаем все шаблоны из папки web/templates
func init() {
	funcMap := template.FuncMap{
		// truncate обрезает текст до N рун и добавляет многоточие — используется
		// для формирования meta description (оптимальная длина ~150-160 символов).
		"truncate": func(s string, n int) string {
			r := []rune(s)
			if len(r) <= n {
				return s
			}
			return string(r[:n]) + "…"
		},
		// initial возвращает первую букву имени в верхнем регистре — используется
		// для аватара-заглушки в шапке авторизованного пользователя.
		"initial": func(s string) string {
			r := []rune(strings.ToUpper(s))
			if len(r) == 0 {
				return "?"
			}
			return string(r[:1])
		},
		// videoMimeType выбирает mime для <source> — HLS-плейлисты из MinIO
		// заливаются как .m3u8, старые демо-эпизоды остаются обычным .mp4.
		"videoMimeType": func(url string) string {
			if strings.HasSuffix(url, ".m3u8") {
				return "application/x-mpegURL"
			}
			return "video/mp4"
		},
		// add/subtract — арифметика для пагинации в шаблонах (/admin/users)
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
	}
	templates = template.Must(template.New("").Funcs(funcMap).ParseGlob("web/templates/*.html"))
	fs := http.FileServer(http.Dir("web/static"))
	http.Handle("/static/", http.StripPrefix("/static/", cacheStatic(fs)))
}

// cacheStatic добавляет Cache-Control к статике (css/js/img/video) — без него
// браузер перезапрашивает те же файлы на каждом визите. Имена файлов не
// версионируются, поэтому TTL умеренный (1 день), а не "immutable" навечно.
func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		next.ServeHTTP(w, r)
	})
}

// gzipMiddleware сжимает текстовые ответы (HTML/CSS/JS/JSON) — картинки и
// видео уже сжаты форматом, повторное сжатие им не даёт выигрыша, поэтому
// сжимаем только по запросу клиента (Accept-Encoding) через стандартный
// compress/gzip, без внешних зависимостей.
type gzipResponseWriter struct {
	http.ResponseWriter
	gz *gzip.Writer
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.gz.Write(b)
}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /static/ уже раздаёт бинарные файлы (картинки/видео) через
		// http.ServeContent, который поддерживает Range-запросы (перемотка
		// видео) — gzip-обёртка это сломает, поэтому пропускаем её.
		//
		// WebSocket-апгрейды (Connection: Upgrade) тоже нужно пропускать не
		// обёрнутыми: gorilla/websocket требует от http.ResponseWriter
		// интерфейс http.Hijacker, а gzipResponseWriter его не реализует.
		// Если клиент шлёт Accept-Encoding: gzip на хендшейк (это делает
		// Safari, но не все браузеры/клиенты — отсюда нестабильность бага),
		// апгрейд получал "500 websocket: response does not implement
		// http.Hijacker" вместо 101 Switching Protocols, и /ws/dm-пуш
		// (сообщения, приглашения в синхропросмотр) молча переставал
		// доставляться именно в тех браузерах, что это делают.
		if strings.HasPrefix(r.URL.Path, "/static/") ||
			strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
			!strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, gz: gz}, r)
	})
}

// render — вспомогательная функция для отрисовки шаблонов
func render(w http.ResponseWriter, tmpl string, data PageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := templates.ExecuteTemplate(w, tmpl, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ---------- Вспомогательные функции ----------

// getUserIDFromSession — единая точка проверки авторизации для всех хендлеров.
// Режим переключается через AUTH_MODE: "cookie" (по умолчанию) читает
// gorilla/sessions cookie, "jwt" — access-токен из заголовка Authorization
// или cookie access_token (см. auth.CurrentMode).
func getUserIDFromSession(r *http.Request) (int, error) {
	if auth.CurrentMode() == auth.ModeJWT {
		return userIDFromAccessToken(r)
	}
	session, err := store.Get(r, "ancen-session")
	if err != nil {
		return 0, err
	}
	userID, ok := session.Values["user_id"].(int)
	if !ok || userID == 0 {
		return 0, fmt.Errorf("не авторизован")
	}
	return userID, nil
}

func userIDFromAccessToken(r *http.Request) (int, error) {
	token, ok := auth.BearerToken(r)
	if !ok {
		if c, err := r.Cookie("access_token"); err == nil {
			token = c.Value
			ok = true
		}
	}
	if !ok || token == "" {
		return 0, fmt.Errorf("не авторизован")
	}
	claims, err := auth.ParseAccessToken(token)
	if err != nil {
		return 0, err
	}
	return claims.UserID, nil
}

// startAuthSession логинит пользователя после проверки пароля: в режиме
// cookie сохраняет gorilla/sessions cookie как раньше, в режиме jwt — выдаёт
// access/refresh токены и кладёт их в HttpOnly-cookie (access_token,
// refresh_token), чтобы обычная серверная навигация продолжала работать без
// изменений на фронтенде; API-клиенты вместо этого могут слать access-токен
// через заголовок Authorization: Bearer.
func startAuthSession(w http.ResponseWriter, r *http.Request, userID int, username string) error {
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

	if auth.CurrentMode() == auth.ModeJWT {
		accessToken, err := auth.IssueAccessToken(userID, isUserAdmin(userID))
		if err != nil {
			return err
		}
		refreshToken, err := auth.IssueRefreshToken(db, userID)
		if err != nil {
			return err
		}
		setAuthCookies(w, secure, accessToken, refreshToken)
		return nil
	}

	session, _ := store.Get(r, "ancen-session")
	session.Values["user_id"] = userID
	session.Values["username"] = username
	session.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400 * 7,
	}
	return session.Save(r, w)
}

func setAuthCookies(w http.ResponseWriter, secure bool, accessToken, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(auth.AccessTokenTTL.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(auth.RefreshTokenTTL.Seconds()),
	})
}

func clearAuthCookies(w http.ResponseWriter, secure bool) {
	for _, name := range []string{"access_token", "refresh_token"} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})
	}
}

// isUserAdmin проверяет роль is_admin в БД — используется для защиты
// чувствительных операций (например, /api/admin/upload-video) независимо
// от режима аутентификации.
func isUserAdmin(userID int) bool {
	var isAdmin bool
	if err := db.QueryRow("SELECT is_admin FROM users WHERE id = ?", userID).Scan(&isAdmin); err != nil {
		return false
	}
	return isAdmin
}

// currentAvatarURL — для admin-хедера, показывает загруженную аватарку вместо
// кружка с инициалом, если она есть.
func currentAvatarURL(userID int) string {
	var avatarURL string
	db.QueryRow("SELECT avatar_url FROM users WHERE id = ?", userID).Scan(&avatarURL)
	return avatarURL
}

// currentUsername возвращает имя пользователя для гостевого/авторизованного
// хедера, либо "" для гостя. В режиме cookie берётся из сессии без похода в
// БД; в режиме jwt — из access-токена по userID.
func currentUsername(r *http.Request) string {
	if auth.CurrentMode() == auth.ModeJWT {
		userID, err := userIDFromAccessToken(r)
		if err != nil {
			return ""
		}
		var username string
		db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
		return username
	}
	session, err := store.Get(r, "ancen-session")
	if err != nil {
		return ""
	}
	username, _ := session.Values["username"].(string)
	return username
}

// ---------- СИСТЕМА АЧИВОК И УРОВНЕЙ ----------

// Achievement определяет одну ачивку
type Achievement struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Icon        string `json:"icon"`
}

// UserAchievement — полученная ачивка пользователя
type UserAchievement struct {
	AchievementID string `json:"achievement_id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Icon          string `json:"icon"`
	Category      string `json:"category"`
	UnlockedAt    string `json:"unlocked_at"`
}

// UserLevelInfo — информация об уровне пользователя
type UserLevelInfo struct {
	Level       int `json:"level"`
	XP          int `json:"xp"`
	NextLevelXP int `json:"next_level_xp"`
	XPPercent   int `json:"xp_percent"` // процент до следующего уровня (0-100)
}

// Логин: заглавная латинская буква, затем латиница/цифры/подчёркивание —
// защита от визуально путающихся пар вроде "Misha"/"Миша" (Safari путал
// сохранённые пароли между двумя разными аккаунтами одного пользователя).
var usernameRe = regexp.MustCompile(`^[A-Z][A-Za-z0-9_]{2,19}$`)

// Все доступные ачивки
var achievements = []Achievement{
	// Эмоции
	{ID: "first_emotion", Name: "Первая эмоция", Description: "Поставить первую эмоцию", Category: "emotions", Icon: "😭"},
	{ID: "emotional_100", Name: "Эмоциональный", Description: "Поставить 100 эмоций", Category: "emotions", Icon: "🔥"},
	{ID: "master_reactions_500", Name: "Мастер реакций", Description: "Поставить 500 эмоций", Category: "emotions", Icon: "🤯"},
	{ID: "all_shades", Name: "Все оттенки", Description: "Использовать все 5 типов эмоций хотя бы раз", Category: "emotions", Icon: "🥰"},
	{ID: "peak_emotion", Name: "Пик эмоций", Description: "Поставить эмоцию на самом популярном таймкоде эпизода", Category: "emotions", Icon: "💢"},
	// Комментарии
	{ID: "first_comment", Name: "Первый комментарий", Description: "Оставить первый комментарий", Category: "comments", Icon: "💬"},
	{ID: "talkative_50", Name: "Говорливый", Description: "Оставить 50 комментариев", Category: "comments", Icon: "🗣️"},
	{ID: "timeline_master", Name: "Таймкод-мастер", Description: "Оставить 10 комментариев на разных таймкодах", Category: "comments", Icon: "⏱️"},
	// Просмотр
	{ID: "guardian_10", Name: "Страж эпизодов", Description: "Посмотреть 10 эпизодов до конца", Category: "viewing", Icon: "🛡️"},
	{ID: "marathoner", Name: "Марафонец", Description: "Посмотреть 5 эпизодов подряд (сессия > 2 часов)", Category: "viewing", Icon: "🏃"},
	{ID: "completer", Name: "Завершатель", Description: "Досмотреть сезон полностью", Category: "viewing", Icon: "🏁"},
	// Особые
	{ID: "early_bird", Name: "Ранний пташка", Description: "Зарегистрироваться в первую неделю запуска", Category: "special", Icon: "🐦"},
	{ID: "expert_50", Name: "Эксперт", Description: "Посмотреть более 50 эпизодов", Category: "special", Icon: "🎓"},
	{ID: "timekeeper", Name: "Хранитель таймкодов", Description: "Оставить 20 эмоций с погрешностью <1 сек", Category: "special", Icon: "⏰"},
	{ID: "friendly", Name: "Дружелюбный", Description: "Добавить 5 друзей", Category: "special", Icon: "🤝"},
	{ID: "popular", Name: "Популярный", Description: "Получить 10 лайков на своих комментариях", Category: "comments", Icon: "⭐"},
}

// Уровни: сколько всего XP нужно набрать для каждого уровня.
// Кривая квадратичная — первые уровни быстрые (дофамин новичку), дальше резко
// сложнее. При dailyXPCap=150 (см. addXP) набрать максимальный уровень (12)
// быстрее чем за ~75 дней (11284/150) физически невозможно, даже если
// проспамить реакциями — это и есть защита от "прошёл всё за неделю".
// Обычный активный пользователь (без выжимания дневного лимита) наберёт
// макс. уровень за ~2-3 месяца.
var levelXPRequirements = buildLevelXPRequirements(12)

// animeGenreList — фиксированный список жанров для мультиселекта в админке.
// Жанры по-прежнему хранятся в anime.genres как CSV-строка (фильтр в
// searchHandler уже работает через LIKE по этой строке) — фиксированный
// список тут только чтобы админ не мог напечатать опечатку/дубликат жанра
// (напр. "Экшен" и "экшн" как разные жанры), из-за которой фильтр на
// /search молча переставал бы находить часть тайтлов.
var animeGenreList = []string{
	"Экшен", "Приключения", "Комедия", "Драма", "Фэнтези", "Ужасы",
	"Меха", "Музыка", "Детектив", "Психологическое", "Романтика",
	"Фантастика", "Спорт", "Сверхъестественное", "Триллер",
	"Повседневность", "Военное", "Исторический", "Демоны", "Магия",
}

func buildLevelXPRequirements(maxLevel int) []int {
	req := make([]int, maxLevel+1) // index 0 не используется (уровень 0)
	for i := 1; i <= maxLevel; i++ {
		req[i] = req[i-1] + 14*i*i + 28*i
	}
	return req
}

// levelBadge — значок у имени за уровень (бесплатная косметика за активность,
// автоматический, без выбора пользователем — см. тот же принцип, что и рамки
// аватара в avatarFramePresets, но проще: не нужен UI выбора).
func levelBadge(level int) string {
	switch {
	case level >= 12:
		return "💎"
	case level >= 9:
		return "🥇"
	case level >= 6:
		return "🥈"
	case level >= 3:
		return "🥉"
	default:
		return ""
	}
}

// levelColor — цвет выделения комментария по уровню автора, тот же принцип,
// что levelBadge (автоматически, без выбора пользователем).
func levelColor(level int) string {
	switch {
	case level >= 12:
		return "#8A9BFF"
	case level >= 9:
		return "#FFCC00"
	case level >= 6:
		return "#C0C0C0"
	case level >= 3:
		return "#9A5B32"
	default:
		return ""
	}
}

// getLevelInfo возвращает уровень по количеству XP
func getLevelInfo(xp int) UserLevelInfo {
	level := 1
	for i := 1; i < len(levelXPRequirements); i++ {
		if xp >= levelXPRequirements[i] {
			level = i + 1
		} else {
			break
		}
	}
	nextLevelXP := 0
	if level < len(levelXPRequirements) {
		nextLevelXP = levelXPRequirements[level]
	} else {
		nextLevelXP = levelXPRequirements[len(levelXPRequirements)-1] + 5000*(level-len(levelXPRequirements)+1)
	}
	xpPercent := 0
	if nextLevelXP > 0 {
		xpPercent = xp * 100 / nextLevelXP
		if xpPercent > 100 {
			xpPercent = 100
		}
	}
	return UserLevelInfo{
		Level:       level,
		XP:          xp,
		NextLevelXP: nextLevelXP,
		XPPercent:   xpPercent,
	}
}

// Анти-фарм: без этих ограничений пользователь может проспамить реакциями/
// комментариями на таймкодах и пройти все уровни за один вечер, что убивает
// смысл долгой прогрессии (см. maxLevel в buildLevelXPRequirements).
const (
	emotionXP               = 5
	commentXP               = 10
	maxXPEmotionsPerEpisode = 20  // реакции сверх лимита сохраняются и видны в ленте, но не дают XP
	maxXPCommentsPerEpisode = 5   // то же для комментариев
	dailyXPCap              = 150 // суммарный потолок начисления XP в сутки
)

// ---------- Ретеншн-механика: бесплатный месяц Premium за активность ----------
// См. 18_Монетизация_и_уровни.md. Условие: 20 из 30 дней активности + 15
// по-настоящему досмотренных эпизодов (не перемотанных до конца).
const (
	progressHeartbeatCreditCap  = 8   // сек, чуть больше интервала хартбита плеера (5с) — запас на джиттер сети
	retentionWatchThresholdSec  = 600 // 10 минут реально накопленного просмотра = эпизод "засчитан"
	retentionWindowDays         = 30  // скользящее окно, а не календарный месяц — проще и не хуже по сути
	retentionActiveDaysRequired = 20  // из 30
	retentionEpisodesRequired   = 15  // "по-настоящему" досмотренных эпизодов за то же окно
	retentionRewardDays         = 30  // на сколько дней выдаётся Premium
)

// apiRetentionProgressHandler — GET /api/retention-progress — для показа
// прогресса к бесплатному месяцу подписки в профиле.
func apiRetentionProgressHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var claimed bool
	db.QueryRow("SELECT retention_reward_claimed FROM users WHERE id = ?", userID).Scan(&claimed)

	windowStart := time.Now().AddDate(0, 0, -(retentionWindowDays - 1)).Format("2006-01-02")
	var activeDays, watchedEpisodes int
	db.QueryRow("SELECT COUNT(*) FROM user_daily_visits WHERE user_id = ? AND day >= ?", userID, windowStart).Scan(&activeDays)
	db.QueryRow(`
		SELECT COUNT(*) FROM user_progress
		WHERE user_id = ? AND watched_seconds >= ? AND updated_at >= ?
	`, userID, retentionWatchThresholdSec, windowStart).Scan(&watchedEpisodes)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"claimed":            claimed,
		"active_days":        activeDays,
		"active_days_needed": retentionActiveDaysRequired,
		"episodes":           watchedEpisodes,
		"episodes_needed":    retentionEpisodesRequired,
	})
}

// checkRetentionReward проверяет условия ретеншн-награды и выдаёт Premium на
// retentionRewardDays, если пользователь их выполнил и ещё не получал награду
// раньше (retention_reward_claimed — разово за всё время жизни аккаунта).
// Дешёвый ранний выход: для подавляющего большинства вызовов (уже получили
// награду, или совсем свежий аккаунт) достаточно первого запроса.
func checkRetentionReward(userID int) {
	var claimed bool
	if err := db.QueryRow("SELECT retention_reward_claimed FROM users WHERE id = ?", userID).Scan(&claimed); err != nil || claimed {
		return
	}

	windowStart := time.Now().AddDate(0, 0, -(retentionWindowDays - 1)).Format("2006-01-02")

	var activeDays int
	db.QueryRow("SELECT COUNT(*) FROM user_daily_visits WHERE user_id = ? AND day >= ?", userID, windowStart).Scan(&activeDays)
	if activeDays < retentionActiveDaysRequired {
		return
	}

	var watchedEpisodes int
	db.QueryRow(`
		SELECT COUNT(*) FROM user_progress
		WHERE user_id = ? AND watched_seconds >= ? AND updated_at >= ?
	`, userID, retentionWatchThresholdSec, windowStart).Scan(&watchedEpisodes)
	if watchedEpisodes < retentionEpisodesRequired {
		return
	}

	until := time.Now().AddDate(0, 0, retentionRewardDays)
	if _, err := db.Exec(
		"UPDATE users SET is_premium = 1, premium_until = ?, retention_reward_claimed = 1 WHERE id = ?",
		until, userID,
	); err != nil {
		log.Printf("checkRetentionReward: не удалось выдать награду user_id=%d: %v", userID, err)
	}
}

// addXP начисляет XP пользователю с учётом суточного лимита (dailyXPCap).
// ponytail: чтение grantedToday и запись — не одна транзакция, при
// параллельных вызовах для одного user_id возможна гонка (оба пройдут
// проверку лимита до записи), но цена ошибки низкая (немного лишнего XP за
// день); добавить транзакцию/FOR UPDATE, если станет реальной проблемой.
func addXP(userID int, amount int) {
	var grantedToday int
	err := db.QueryRow(`
		SELECT xp FROM user_xp_daily WHERE user_id = ? AND day = CURDATE()
	`, userID).Scan(&grantedToday)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("addXP: чтение дневного лимита: %v", err)
		return
	}
	remaining := dailyXPCap - grantedToday
	if remaining <= 0 {
		return
	}
	if amount > remaining {
		amount = remaining
	}

	if _, err := db.Exec(`
		INSERT INTO user_xp (user_id, xp) VALUES (?, ?)
		ON DUPLICATE KEY UPDATE xp = xp + VALUES(xp)
	`, userID, amount); err != nil {
		log.Printf("addXP error: %v", err)
		return
	}
	if _, err := db.Exec(`
		INSERT INTO user_xp_daily (user_id, day, xp) VALUES (?, CURDATE(), ?)
		ON DUPLICATE KEY UPDATE xp = xp + VALUES(xp)
	`, userID, amount); err != nil {
		log.Printf("addXP: запись дневного лимита: %v", err)
	}
}

// awardEmotionXP начисляет XP за реакцию, если пользователь ещё не превысил
// лимит XP-реакций на этот эпизод (сама реакция при этом уже сохранена в БД,
// поэтому count включает и её саму).
// ponytail: COUNT после INSERT — при параллельных запросах того же
// пользователя возможна гонка (оба увидят count<=cap и оба получат XP), но
// цена ошибки — пара лишних XP, не критично; добавить транзакцию с FOR
// UPDATE, если фарм через несколько вкладок станет реальной проблемой.
func awardEmotionXP(userID, episodeID int) {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM emotions WHERE user_id = ? AND episode_id = ?", userID, episodeID).Scan(&count); err != nil {
		log.Printf("awardEmotionXP: %v", err)
		return
	}
	if count <= maxXPEmotionsPerEpisode {
		addXP(userID, emotionXP)
	}
}

// awardCommentXP — то же самое для комментариев.
func awardCommentXP(userID, episodeID int) {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM comments WHERE user_id = ? AND episode_id = ?", userID, episodeID).Scan(&count); err != nil {
		log.Printf("awardCommentXP: %v", err)
		return
	}
	if count <= maxXPCommentsPerEpisode {
		addXP(userID, commentXP)
	}
}

// checkAndUnlockAchievements проверяет и разблокирует ачивки для пользователя
// checkAndUnlockAchievements проверяет условия ачивок и разблокирует выполненные.
// Возвращает только те, что были разблокированы именно этим вызовом — нужно
// для тоста "Достижение получено" на фронтенде (чтобы не показывать его повторно
// на каждое действие после того, как ачивка уже разблокирована раньше).
func checkAndUnlockAchievements(userID int) []Achievement {
	var emotionCount, commentCount int
	var usedEmotions string
	var episodeCount int

	db.QueryRow("SELECT COUNT(*) FROM emotions WHERE user_id = ?", userID).Scan(&emotionCount)
	db.QueryRow("SELECT COUNT(*) FROM comments WHERE user_id = ?", userID).Scan(&commentCount)
	db.QueryRow("SELECT COUNT(DISTINCT episode_id) FROM emotions WHERE user_id = ?", userID).Scan(&episodeCount)

	rows, err := db.Query("SELECT DISTINCT emotion_type FROM emotions WHERE user_id = ?", userID)
	if err == nil {
		var types []string
		for rows.Next() {
			var t string
			rows.Scan(&t)
			types = append(types, t)
		}
		rows.Close()
		usedEmotions = strings.Join(types, ",")
	}

	checks := []struct {
		id    string
		check func() bool
	}{
		{"first_emotion", func() bool { return emotionCount >= 1 }},
		{"emotional_100", func() bool { return emotionCount >= 100 }},
		{"master_reactions_500", func() bool { return emotionCount >= 500 }},
		{"all_shades", func() bool {
			all := []string{"😭", "🔥", "🤯", "🥰", "💢"}
			for _, e := range all {
				if !strings.Contains(usedEmotions, e) {
					return false
				}
			}
			return emotionCount >= 5
		}},
		{"first_comment", func() bool { return commentCount >= 1 }},
		{"talkative_50", func() bool { return commentCount >= 50 }},
		{"timeline_master", func() bool {
			var distinctTimestamps int
			db.QueryRow("SELECT COUNT(DISTINCT timestamp_sec) FROM comments WHERE user_id = ?", userID).Scan(&distinctTimestamps)
			return distinctTimestamps >= 10
		}},
		{"guardian_10", func() bool { return episodeCount >= 10 }},
		{"expert_50", func() bool { return episodeCount >= 50 }},
		{"friendly", func() bool {
			var friendCount int
			db.QueryRow("SELECT COUNT(*) FROM friendships WHERE status = 'accepted' AND (requester_id = ? OR addressee_id = ?)", userID, userID).Scan(&friendCount)
			return friendCount >= 5
		}},
		{"popular", func() bool {
			var likeCount int
			db.QueryRow(`SELECT COUNT(*) FROM comment_likes cl JOIN comments c ON cl.comment_id = c.id WHERE c.user_id = ?`, userID).Scan(&likeCount)
			return likeCount >= 10
		}},
	}

	var newlyUnlocked []Achievement
	for _, c := range checks {
		if c.check() && unlockAchievement(userID, c.id) {
			for _, a := range achievements {
				if a.ID == c.id {
					newlyUnlocked = append(newlyUnlocked, a)
					break
				}
			}
		}
	}
	return newlyUnlocked
}

// unlockAchievement разблокирует ачивку, если ещё не разблокирована.
// Возвращает true, если ачивка была разблокирована именно этим вызовом (а не раньше).
func unlockAchievement(userID int, achievementID string) bool {
	res, err := db.Exec(`
		INSERT IGNORE INTO user_achievements (user_id, achievement_id)
		VALUES (?, ?)
	`, userID, achievementID)
	if err != nil {
		log.Printf("unlockAchievement error: %v", err)
		return false
	}
	affected, _ := res.RowsAffected()
	return affected > 0
}

// getUserAchievements возвращает все ачивки пользователя
func getUserAchievements(userID int) []UserAchievement {
	rows, err := db.Query(`
		SELECT ua.achievement_id, ua.unlocked_at
		FROM user_achievements ua
		WHERE ua.user_id = ?
		ORDER BY ua.unlocked_at ASC
	`, userID)
	if err != nil {
		log.Printf("getUserAchievements error: %v", err)
		return nil
	}
	defer rows.Close()

	unlocked := make(map[string]string)
	for rows.Next() {
		var id, unlockedAt string
		if err := rows.Scan(&id, &unlockedAt); err != nil {
			continue
		}
		unlocked[id] = unlockedAt
	}

	var result []UserAchievement
	for _, a := range achievements {
		if unlockedAt, ok := unlocked[a.ID]; ok {
			result = append(result, UserAchievement{
				AchievementID: a.ID,
				Name:          a.Name,
				Description:   a.Description,
				Icon:          a.Icon,
				Category:      a.Category,
				UnlockedAt:    unlockedAt,
			})
		}
	}
	return result
}

// ===== Друзья =====

type FriendInfo struct {
	UserID           int
	Username         string
	AvatarURL        string
	AvatarFrameColor string
	Level            int
}

type FriendRequestInfo struct {
	RequestID int
	UserID    int
	Username  string
	AvatarURL string
	Level     int
}

func friendInfoRows(rows *sql.Rows) []FriendInfo {
	defer rows.Close()
	var result []FriendInfo
	for rows.Next() {
		var f FriendInfo
		var avatarFrame string
		var xp int
		if rows.Scan(&f.UserID, &f.Username, &f.AvatarURL, &avatarFrame, &xp) == nil {
			if fr, ok := avatarFrameByID(avatarFrame); ok && fr.ID != "" {
				f.AvatarFrameColor = fr.Color
			} else {
				f.AvatarFrameColor = "#ffffff"
			}
			f.Level = getLevelInfo(xp).Level
			result = append(result, f)
		}
	}
	return result
}

// TopUserInfo — строка блока "Топ пользователей" на главной.
type TopUserInfo struct {
	Username  string
	AvatarURL string
	Level     int
}

// getTopUsers возвращает первых limit пользователей по XP (убывание) для
// блока "Топ пользователей" на главной — раньше это был захардкоженный
// список из трёх выдуманных имён.
func getTopUsers(limit int) []TopUserInfo {
	rows, err := db.Query(`
		SELECT u.username, u.avatar_url, ux.xp
		FROM user_xp ux
		JOIN users u ON u.id = ux.user_id
		ORDER BY ux.xp DESC
		LIMIT ?
	`, limit)
	if err != nil {
		log.Printf("getTopUsers error: %v", err)
		return nil
	}
	defer rows.Close()
	var result []TopUserInfo
	for rows.Next() {
		var t TopUserInfo
		var xp int
		if rows.Scan(&t.Username, &t.AvatarURL, &xp) == nil {
			t.Level = getLevelInfo(xp).Level
			result = append(result, t)
		}
	}
	return result
}

// getFriends возвращает принятых друзей пользователя.
func getFriends(userID int) []FriendInfo {
	rows, err := db.Query(`
		SELECT u.id, u.username, u.avatar_url, u.avatar_frame, COALESCE(ux.xp, 0)
		FROM friendships f
		JOIN users u ON u.id = CASE WHEN f.requester_id = ? THEN f.addressee_id ELSE f.requester_id END
		LEFT JOIN user_xp ux ON ux.user_id = u.id
		WHERE f.status = 'accepted' AND (f.requester_id = ? OR f.addressee_id = ?)
		ORDER BY u.username
	`, userID, userID, userID)
	if err != nil {
		log.Printf("getFriends error: %v", err)
		return nil
	}
	return friendInfoRows(rows)
}

// FriendWatchingInfo — строка ленты активности друзей ("Х сейчас смотрит Y").
type FriendWatchingInfo struct {
	Username   string
	AvatarURL  string
	AnimeID    int
	AnimeTitle string
	EpisodeID  int
	EpisodeNum int
}

// friendsWatchingWindow — "сейчас смотрит" считается по свежести
// user_progress.updated_at (плеер пишет его раз в 5с, см. /api/progress) —
// не требует отдельной realtime-инфраструктуры, переиспользует то, что уже
// есть. Уважает users.show_watching_activity (решено 2026-08-14).
const friendsWatchingWindow = 3 * time.Minute

// getFriendsWatchingNow возвращает друзей, которые прямо сейчас смотрят
// что-то (свежий прогресс за friendsWatchingWindow) и не скрыли эту активность.
func getFriendsWatchingNow(userID int) []FriendWatchingInfo {
	rows, err := db.Query(`
		SELECT u.username, u.avatar_url, a.id, a.title, e.id, e.episode_num
		FROM friendships f
		JOIN users u ON u.id = CASE WHEN f.requester_id = ? THEN f.addressee_id ELSE f.requester_id END
		JOIN user_progress up ON up.user_id = u.id
		JOIN episodes e ON e.id = up.episode_id
		JOIN anime a ON a.id = e.anime_id
		WHERE f.status = 'accepted' AND (f.requester_id = ? OR f.addressee_id = ?)
			AND u.show_watching_activity = 1
			AND up.updated_at >= ?
		ORDER BY up.updated_at DESC
	`, userID, userID, userID, time.Now().Add(-friendsWatchingWindow))
	if err != nil {
		log.Printf("getFriendsWatchingNow error: %v", err)
		return nil
	}
	defer rows.Close()

	var result []FriendWatchingInfo
	for rows.Next() {
		var f FriendWatchingInfo
		if rows.Scan(&f.Username, &f.AvatarURL, &f.AnimeID, &f.AnimeTitle, &f.EpisodeID, &f.EpisodeNum) == nil {
			result = append(result, f)
		}
	}
	return result
}

// getPendingIncoming возвращает входящие заявки в друзья.
func getPendingIncoming(userID int) []FriendRequestInfo {
	rows, err := db.Query(`
		SELECT f.id, u.id, u.username, u.avatar_url, COALESCE(ux.xp, 0)
		FROM friendships f
		JOIN users u ON u.id = f.requester_id
		LEFT JOIN user_xp ux ON ux.user_id = u.id
		WHERE f.status = 'pending' AND f.addressee_id = ?
		ORDER BY f.created_at DESC
	`, userID)
	if err != nil {
		log.Printf("getPendingIncoming error: %v", err)
		return nil
	}
	defer rows.Close()
	var result []FriendRequestInfo
	for rows.Next() {
		var r FriendRequestInfo
		var xp int
		if rows.Scan(&r.RequestID, &r.UserID, &r.Username, &r.AvatarURL, &xp) == nil {
			r.Level = getLevelInfo(xp).Level
			result = append(result, r)
		}
	}
	return result
}

// getFriendshipStatus сообщает состояние связи между viewerID и otherID:
// "self", "friends", "pending_sent", "pending_received" или "none".
func getFriendshipStatus(viewerID, otherID int) string {
	if viewerID == otherID {
		return "self"
	}
	var status string
	var requesterID int
	err := db.QueryRow(`
		SELECT status, requester_id FROM friendships
		WHERE (requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?)
	`, viewerID, otherID, otherID, viewerID).Scan(&status, &requesterID)
	if err == sql.ErrNoRows {
		return "none"
	}
	if err != nil {
		log.Printf("getFriendshipStatus error: %v", err)
		return "none"
	}
	if status == "accepted" {
		return "friends"
	}
	if requesterID == viewerID {
		return "pending_sent"
	}
	return "pending_received"
}

// sendFriendRequest отправляет заявку в друзья по username. Если у адресата уже
// есть встречная заявка — заявки автоматически становятся взаимной дружбой,
// не плодя дублирующую запись.
func sendFriendRequest(fromID int, toUsername string) (string, error) {
	var toID int
	if err := db.QueryRow("SELECT id FROM users WHERE username = ?", toUsername).Scan(&toID); err != nil {
		return "", fmt.Errorf("пользователь не найден")
	}
	if toID == fromID {
		return "", fmt.Errorf("нельзя добавить себя в друзья")
	}

	status := getFriendshipStatus(fromID, toID)
	switch status {
	case "friends":
		return "friends", nil
	case "pending_sent":
		return "pending_sent", nil
	case "pending_received":
		// у собеседника уже есть входящая заявка от нас — принимаем её встречную
		if _, err := db.Exec("UPDATE friendships SET status = 'accepted' WHERE requester_id = ? AND addressee_id = ?", toID, fromID); err != nil {
			return "", err
		}
		return "friends", nil
	}

	if _, err := db.Exec("INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?, ?, 'pending')", fromID, toID); err != nil {
		return "", err
	}
	return "pending_sent", nil
}

// respondFriendRequest принимает или отклоняет входящую заявку requestID,
// адресованную userID.
func respondFriendRequest(userID, requestID int, accept bool) error {
	if accept {
		res, err := db.Exec("UPDATE friendships SET status = 'accepted' WHERE id = ? AND addressee_id = ? AND status = 'pending'", requestID, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("заявка не найдена")
		}
		return nil
	}
	res, err := db.Exec("DELETE FROM friendships WHERE id = ? AND addressee_id = ? AND status = 'pending'", requestID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("заявка не найдена")
	}
	return nil
}

// removeFriendship удаляет дружбу (в любую сторону) между userID и otherID.
func removeFriendship(userID, otherID int) error {
	_, err := db.Exec(`
		DELETE FROM friendships
		WHERE status = 'accepted' AND ((requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?))
	`, userID, otherID, otherID, userID)
	return err
}

// createTables создаёт таблицы для системы ачивок и сброса пароля, если их нет
func createTables() {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS user_xp (
			user_id INT PRIMARY KEY,
			xp INT NOT NULL DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS user_xp_daily (
			user_id INT NOT NULL,
			day DATE NOT NULL,
			xp INT NOT NULL DEFAULT 0,
			PRIMARY KEY (user_id, day),
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS user_achievements (
			user_id INT NOT NULL,
			achievement_id VARCHAR(50) NOT NULL,
			unlocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, achievement_id),
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS password_resets (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
			token VARCHAR(64) NOT NULL UNIQUE,
			expires_at DATETIME NOT NULL,
			used TINYINT(1) DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS user_progress (
			user_id INT NOT NULL,
			episode_id INT NOT NULL,
			last_timestamp_sec INT NOT NULL DEFAULT 0,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, episode_id),
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (episode_id) REFERENCES episodes(id)
		)`,
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
			token_hash VARCHAR(64) NOT NULL UNIQUE,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME DEFAULT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS friendships (
			id INT AUTO_INCREMENT PRIMARY KEY,
			requester_id INT NOT NULL,
			addressee_id INT NOT NULL,
			status ENUM('pending','accepted') NOT NULL DEFAULT 'pending',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE KEY uniq_pair (requester_id, addressee_id),
			FOREIGN KEY (requester_id) REFERENCES users(id),
			FOREIGN KEY (addressee_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS favorites (
			user_id INT NOT NULL,
			anime_id INT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, anime_id),
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (anime_id) REFERENCES anime(id)
		)`,
		`CREATE TABLE IF NOT EXISTS favorite_episodes (
			user_id INT NOT NULL,
			episode_id INT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, episode_id),
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (episode_id) REFERENCES episodes(id)
		)`,
		// Лог визитов страниц — источник для графиков /admin (посещения,
		// длительность сессии, устройства). Пишется middleware'ом logVisit
		// в main(). session_id — sha256 от cookie сессии, не сырое значение.
		`CREATE TABLE IF NOT EXISTS admin_visits (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			user_id INT DEFAULT NULL,
			session_id CHAR(64) NOT NULL,
			path VARCHAR(255) NOT NULL,
			device VARCHAR(16) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_created_at (created_at),
			INDEX idx_session (session_id, created_at)
		)`,
		// Единственная строка конфигурации сайта — сейчас только maintenance mode
		// (/admin/settings). Кэшируется в maintenanceMode при старте main().
		`CREATE TABLE IF NOT EXISTS app_settings (
			id TINYINT PRIMARY KEY DEFAULT 1,
			maintenance_mode BOOLEAN NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS comment_likes (
			user_id INT NOT NULL,
			comment_id INT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, comment_id),
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (comment_id) REFERENCES comments(id)
		)`,
		// Личные сообщения. read_at NULL = непрочитано. Индекс по паре
		// (sender_id, recipient_id) и обратный — для быстрой выборки переписки
		// с конкретным собеседником и списка диалогов.
		`CREATE TABLE IF NOT EXISTS messages (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			sender_id INT NOT NULL,
			recipient_id INT NOT NULL,
			text VARCHAR(1000) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			read_at TIMESTAMP NULL DEFAULT NULL,
			FOREIGN KEY (sender_id) REFERENCES users(id),
			FOREIGN KEY (recipient_id) REFERENCES users(id),
			INDEX idx_sender_recipient (sender_id, recipient_id, created_at),
			INDEX idx_recipient_sender (recipient_id, sender_id, created_at)
		)`,
		// Один день = одна строка, независимо от числа визитов за день —
		// источник "20 из 30 дней" для ретеншн-механики (см. checkRetentionReward).
		`CREATE TABLE IF NOT EXISTS user_daily_visits (
			user_id INT NOT NULL,
			day DATE NOT NULL,
			PRIMARY KEY (user_id, day),
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
	}
	for _, q := range tables {
		if _, err := db.Exec(q); err != nil {
			log.Printf("createTable error: %v", err)
		}
	}
	log.Println("Таблицы ачивок и сброса пароля проверены/созданы")

	if _, err := db.Exec("INSERT IGNORE INTO app_settings (id, maintenance_mode) VALUES (1, 0)"); err != nil {
		log.Printf("app_settings init error: %v", err)
	}

	// Добавляем поле email в users, если его нет
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN email VARCHAR(255) DEFAULT '' AFTER username"); err != nil {
		log.Printf("ALTER TABLE users (email) может уже существовать: %v", err)
	}
	// Добавляем поле email_confirmed в users, если его нет
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN email_confirmed TINYINT(1) DEFAULT 0 AFTER email"); err != nil {
		log.Printf("ALTER TABLE users (email_confirmed) может уже существовать: %v", err)
	}
	// Роль администратора — заменяет статический ADMIN_UPLOAD_TOKEN, назначается
	// вручную через SQL (UPDATE users SET is_admin = 1 WHERE id = ...), пока нет админ-панели
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN is_admin TINYINT(1) DEFAULT 0 AFTER password_hash"); err != nil {
		log.Printf("ALTER TABLE users (is_admin) может уже существовать: %v", err)
	}
	// Блокировка пользователя из админ-панели (/admin/users) — банит вход, не удаляя аккаунт
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN is_banned TINYINT(1) DEFAULT 0 AFTER is_admin"); err != nil {
		log.Printf("ALTER TABLE users (is_banned) может уже существовать: %v", err)
	}
	// Таймкоды автоскипа опенинга/эндинга (NULL = не задано, кнопка на плеере не показывается)
	for _, col := range []string{"intro_start_sec", "intro_end_sec", "outro_start_sec", "outro_end_sec"} {
		if _, err := db.Exec("ALTER TABLE episodes ADD COLUMN " + col + " INT DEFAULT NULL"); err != nil {
			log.Printf("ALTER TABLE episodes (%s) может уже существовать: %v", col, err)
		}
	}
	// Группировка эпизодов по сезонам на странице аниме
	if _, err := db.Exec("ALTER TABLE episodes ADD COLUMN season INT NOT NULL DEFAULT 1"); err != nil {
		log.Printf("ALTER TABLE episodes (season) может уже существовать: %v", err)
	}
	// Превью-картинка эпизода (админка) — отдельно от poster_url аниме
	if _, err := db.Exec("ALTER TABLE episodes ADD COLUMN poster_url VARCHAR(500) DEFAULT ''"); err != nil {
		log.Printf("ALTER TABLE episodes (poster_url) может уже существовать: %v", err)
	}
	// Метаданные для карточки аниме (страна/первоисточник/студия/автор/режиссёр) — из Figma
	for _, col := range []string{"country", "source_type", "studio", "author", "director"} {
		if _, err := db.Exec("ALTER TABLE anime ADD COLUMN " + col + " VARCHAR(255) DEFAULT ''"); err != nil {
			log.Printf("ALTER TABLE anime (%s) может уже существовать: %v", col, err)
		}
	}
	if _, err := db.Exec("ALTER TABLE anime ADD COLUMN year VARCHAR(16) DEFAULT ''"); err != nil {
		log.Printf("ALTER TABLE anime (year) может уже существовать: %v", err)
	}
	// Широкий баннер (для карточек-баннеров) — отдельно от узкого poster_url
	// (постер на странице аниме/в обсуждаемых), см. запрос пользователя 2026-08-18.
	if _, err := db.Exec("ALTER TABLE anime ADD COLUMN banner_url VARCHAR(500) DEFAULT ''"); err != nil {
		log.Printf("ALTER TABLE anime (banner_url) может уже существовать: %v", err)
	}
	// Premium-подписка: без неё реакции/комментарии видны только до текущего прогресса
	// просмотра (анти-спойлер), см. isPremiumUser/watchedUpToSec
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN is_premium TINYINT(1) NOT NULL DEFAULT 0"); err != nil {
		log.Printf("ALTER TABLE users (is_premium) может уже существовать: %v", err)
	}
	// Кастомизация профиля: свой аватар (бесплатно всем, см. 18_Монетизация_и_уровни.md)
	// и рамка аватара (пресет, разблокируется уровнем)
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN avatar_url VARCHAR(500) DEFAULT ''"); err != nil {
		log.Printf("ALTER TABLE users (avatar_url) может уже существовать: %v", err)
	}
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN avatar_frame VARCHAR(32) DEFAULT ''"); err != nil {
		log.Printf("ALTER TABLE users (avatar_frame) может уже существовать: %v", err)
	}
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN chart_color VARCHAR(32) DEFAULT ''"); err != nil {
		log.Printf("ALTER TABLE users (chart_color) может уже существовать: %v", err)
	}
	// Приватность ленты активности друзей ("Х сейчас смотрит Y") — по умолчанию
	// включено, пользователь может отключить в профиле.
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN show_watching_activity TINYINT(1) NOT NULL DEFAULT 1"); err != nil {
		log.Printf("ALTER TABLE users (show_watching_activity) может уже существовать: %v", err)
	}
	// Приватность личных сообщений: 'everyone' (бесплатно, по умолчанию) или
	// 'friends_only' (Premium-фича, см. 18_Монетизация_и_уровни.md) — кто
	// может написать пользователю. Значение 'friends_only' у не-Premium
	// игнорируется на сервере (canMessage), не только на UI.
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN dm_privacy VARCHAR(16) NOT NULL DEFAULT 'everyone'"); err != nil {
		log.Printf("ALTER TABLE users (dm_privacy) может уже существовать: %v", err)
	}
	// Ретеншн-механика "бесплатный месяц за активность" (см. 18_Монетизация_и_уровни.md).
	// premium_until — срок действия Premium, выданного этой наградой (NULL — не задан,
	// т.е. обычный бессрочный Premium, включённый вручную через SQL/админку, как раньше).
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN premium_until DATETIME NULL DEFAULT NULL"); err != nil {
		log.Printf("ALTER TABLE users (premium_until) может уже существовать: %v", err)
	}
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN retention_reward_claimed TINYINT(1) NOT NULL DEFAULT 0"); err != nil {
		log.Printf("ALTER TABLE users (retention_reward_claimed) может уже существовать: %v", err)
	}
	// watched_seconds — реально накопленное время просмотра эпизода, отдельно от
	// last_timestamp_sec (позиции для "продолжить с этого места"). Считается по
	// приросту таймкода между хартбитами плеера (раз в 5с), с потолком на прирост —
	// перемотка вперёд не даёт накрутить его мгновенно (см. apiProgressPost).
	if _, err := db.Exec("ALTER TABLE user_progress ADD COLUMN watched_seconds INT NOT NULL DEFAULT 0"); err != nil {
		log.Printf("ALTER TABLE user_progress (watched_seconds) может уже существовать: %v", err)
	}
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN background_url VARCHAR(500) DEFAULT ''"); err != nil {
		log.Printf("ALTER TABLE users (background_url) может уже существовать: %v", err)
	}
	if _, err := db.Exec("ALTER TABLE users ALTER COLUMN background_url SET DEFAULT '" + defaultBackgroundURL + "'"); err != nil {
		log.Printf("ALTER TABLE users (background_url default) не применился: %v", err)
	}
	if _, err := db.Exec("UPDATE users SET background_url = ? WHERE background_url = ''", defaultBackgroundURL); err != nil {
		log.Printf("UPDATE users (background_url для старых аккаунтов) не применился: %v", err)
	}
	// Метки времени для дашборда админки (рост пользователей/реакций по дням).
	// У существующих строк проставится текущий момент — это ожидаемо, метрика
	// "новое за период" станет осмысленной по мере накопления новых данных.
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"); err != nil {
		log.Printf("ALTER TABLE users (created_at) может уже существовать: %v", err)
	}
	if _, err := db.Exec("ALTER TABLE emotions ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"); err != nil {
		log.Printf("ALTER TABLE emotions (created_at) может уже существовать: %v", err)
	}
	// Голосовые тикеры — короткие аудиокомментарии, та же таблица/лента, что
	// текстовые: NULL/'' у text, заполнен audio_url, и наоборот. Не отдельная
	// таблица — избегаем дублировать пагинацию/антиспойлер-фильтр/XP-логику,
	// которые уже есть для apiCommentsGet/apiCommentPost.
	if _, err := db.Exec("ALTER TABLE comments ADD COLUMN audio_url VARCHAR(500) DEFAULT ''"); err != nil {
		log.Printf("ALTER TABLE comments (audio_url) может уже существовать: %v", err)
	}
}

const defaultBackgroundURL = "/static/img/profile/default_bg.jpg"

// ---------- Обработчики ----------

// recommendedAnimeCard — карточка аниме для блока "Рекомендуем вам" на главной.
type recommendedAnimeCard struct {
	ID     int
	Title  string
	Poster string
	Genres string
}

// getRecommendedAnime — простая рекомендательная система без ML (решено
// 2026-08-14, см. 13_Дальнейшие_улучшения.md): сначала аниме тех жанров, на
// которых пользователь оставил больше всего реакций/комментариев, затем —
// внутри этого — по общей популярности среди всех пользователей. Гостям и
// пользователям без активности отдаём просто топ по популярности (fallback).
func getRecommendedAnime(userID int, limit int) []recommendedAnimeCard {
	popularityWhere := ""
	args := []interface{}{}

	if userID > 0 {
		genreRows, err := db.Query(`
			SELECT a.genres FROM anime a
			JOIN episodes e ON e.anime_id = a.id
			WHERE a.genres != '' AND (
				e.id IN (SELECT episode_id FROM emotions WHERE user_id = ?)
				OR e.id IN (SELECT episode_id FROM comments WHERE user_id = ?)
			)
		`, userID, userID)
		if err == nil {
			genreWeight := make(map[string]int)
			for genreRows.Next() {
				var genres string
				if genreRows.Scan(&genres) == nil {
					for _, g := range strings.Split(genres, ",") {
						g = strings.TrimSpace(g)
						if g != "" {
							genreWeight[g]++
						}
					}
				}
			}
			genreRows.Close()

			topGenre := ""
			topWeight := 0
			for g, w := range genreWeight {
				if w > topWeight {
					topGenre, topWeight = g, w
				}
			}
			if topGenre != "" {
				popularityWhere = "WHERE a.genres LIKE ?"
				args = append(args, "%"+topGenre+"%")
			}
		}
	}

	query := `
		SELECT a.id, a.title, a.poster_url, a.genres
		FROM anime a
		LEFT JOIN (SELECT e.anime_id, COUNT(*) c FROM user_progress up JOIN episodes e ON e.id = up.episode_id GROUP BY e.anime_id) v ON v.anime_id = a.id
		LEFT JOIN (SELECT e.anime_id, COUNT(*) c FROM emotions em JOIN episodes e ON e.id = em.episode_id GROUP BY e.anime_id) r ON r.anime_id = a.id
		LEFT JOIN (SELECT e.anime_id, COUNT(*) c FROM comments cm JOIN episodes e ON e.id = cm.episode_id GROUP BY e.anime_id) c ON c.anime_id = a.id
		` + popularityWhere + `
		ORDER BY (COALESCE(v.c,0) + COALESCE(r.c,0) + COALESCE(c.c,0)) DESC
		LIMIT ?
	`
	rows, err := db.Query(query, append(args, limit)...)
	if err != nil {
		log.Printf("getRecommendedAnime: %v", err)
		return nil
	}
	defer rows.Close()

	var results []recommendedAnimeCard
	for rows.Next() {
		var c recommendedAnimeCard
		if rows.Scan(&c.ID, &c.Title, &c.Poster, &c.Genres) == nil {
			results = append(results, c)
		}
	}

	// Если рекомендации по жанру пользователя дали слишком мало результатов
	// (мало аниме этого жанра в каталоге) — дополняем общей популярностью,
	// без фильтра по жанру, чтобы блок не выглядел пустым/куцым.
	if popularityWhere != "" && len(results) < limit {
		return getRecommendedAnimeFallback(limit)
	}
	return results
}

// getRecommendedAnimeFallback — топ по популярности без фильтра по жанру.
func getRecommendedAnimeFallback(limit int) []recommendedAnimeCard {
	rows, err := db.Query(`
		SELECT a.id, a.title, a.poster_url, a.genres
		FROM anime a
		LEFT JOIN (SELECT e.anime_id, COUNT(*) c FROM user_progress up JOIN episodes e ON e.id = up.episode_id GROUP BY e.anime_id) v ON v.anime_id = a.id
		LEFT JOIN (SELECT e.anime_id, COUNT(*) c FROM emotions em JOIN episodes e ON e.id = em.episode_id GROUP BY e.anime_id) r ON r.anime_id = a.id
		LEFT JOIN (SELECT e.anime_id, COUNT(*) c FROM comments cm JOIN episodes e ON e.id = cm.episode_id GROUP BY e.anime_id) c ON c.anime_id = a.id
		ORDER BY (COALESCE(v.c,0) + COALESCE(r.c,0) + COALESCE(c.c,0)) DESC
		LIMIT ?
	`, limit)
	if err != nil {
		log.Printf("getRecommendedAnimeFallback: %v", err)
		return nil
	}
	defer rows.Close()

	var results []recommendedAnimeCard
	for rows.Next() {
		var c recommendedAnimeCard
		if rows.Scan(&c.ID, &c.Title, &c.Poster, &c.Genres) == nil {
			results = append(results, c)
		}
	}
	return results
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// "/" зарегистрирован в DefaultServeMux как catch-all: Go отдаёт этот
	// хендлер для ЛЮБОГО пути без отдельного маршрута, так что несуществующие
	// URL нужно ловить здесь и рендерить 404, а не отдавать им главную.
	if r.URL.Path != "/" {
		notFoundHandler(w, r)
		return
	}

	userID, _ := getUserIDFromSession(r)

	// Отдаём реальный контент главной страницы сразу по "/" (важно для SEO —
	// поисковый робот должен видеть контент без JS-редиректа). Прелоадер
	// показывается как визуальный оверлей внутри home.html и просто гаснет,
	// без навигации на отдельный URL.
	var friendsWatching []FriendWatchingInfo
	if userID > 0 {
		friendsWatching = getFriendsWatchingNow(userID)
	}

	data := struct {
		Title            string
		Username         string
		RecommendedAnime []recommendedAnimeCard
		FriendsWatching  []FriendWatchingInfo
		TopUsers         []TopUserInfo
	}{
		Title:            "AniMemory — смотри аниме и делись эмоциями в реальном времени",
		Username:         currentUsername(r),
		RecommendedAnime: getRecommendedAnime(userID, 6),
		FriendsWatching:  friendsWatching,
		TopUsers:         getTopUsers(3),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "home.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	templates.ExecuteTemplate(w, "404.html", PageData{
		Title:    "Страница не найдена — AniMemory",
		Username: currentUsername(r),
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		ip := clientIP(r)

		if locked, remaining := isLoginLocked(username, ip); locked {
			log.Printf("Login blocked (rate limit) for %s from %s, retry in %s", username, ip, remaining.Round(time.Second))
			render(w, "login.html", PageData{Title: "Вход", Error: fmt.Sprintf("Слишком много неудачных попыток. Попробуйте снова через %d мин.", int(remaining.Minutes())+1)})
			return
		}

		var userID int
		var dbPassword string
		var isBanned bool
		err := db.QueryRow("SELECT id, password_hash, is_banned FROM users WHERE username = ?", username).Scan(&userID, &dbPassword, &isBanned)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Println("Login failed: user not found", username)
				registerFailedLogin(username, ip)
				render(w, "login.html", PageData{Title: "Вход", Error: "Неверный логин или пароль"})
			} else {
				log.Println("DB error:", err)
				render(w, "login.html", PageData{Title: "Вход", Error: "Ошибка БД"})
			}
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
		if err != nil {
			log.Println("Login failed: wrong password for", username)
			registerFailedLogin(username, ip)
			render(w, "login.html", PageData{Title: "Вход", Error: "Неверный логин или пароль"})
			return
		}

		if isBanned {
			log.Printf("Login blocked (banned): %s (id=%d)", username, userID)
			render(w, "login.html", PageData{Title: "Вход", Error: "Аккаунт заблокирован администратором"})
			return
		}

		resetLoginAttempts(username, ip)

		if err := startAuthSession(w, r, userID, username); err != nil {
			log.Println("Session save error:", err)
			render(w, "login.html", PageData{Title: "Вход", Error: "Ошибка сохранения сессии"})
			return
		}
		log.Printf("User %s (id=%d) logged in successfully", username, userID)
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}
	render(w, "login.html", PageData{Title: "Вход"})
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !actionLimiter.allow("register:"+clientIP(r), registerRateLimit, registerRateWindow) {
			render(w, "register.html", PageData{Title: "Регистрация", Error: "Слишком много попыток регистрации. Попробуйте позже."})
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		email := r.FormValue("email")

		if username == "" || password == "" {
			render(w, "register.html", PageData{Title: "Регистрация", Error: "Заполните все поля"})
			return
		}

		if !usernameRe.MatchString(username) {
			render(w, "register.html", PageData{Title: "Регистрация", Error: "Логин: только латиница и цифры, начинается с заглавной буквы, без пробелов (3-20 символов)"})
			return
		}

		if r.FormValue("consent") == "" {
			render(w, "register.html", PageData{Title: "Регистрация", Error: "Нужно согласие на обработку персональных данных"})
			return
		}

		if len(password) < 6 {
			render(w, "register.html", PageData{Title: "Регистрация", Error: "Пароль должен быть не менее 6 символов"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
		if err != nil {
			render(w, "register.html", PageData{Title: "Регистрация", Error: "Ошибка хеширования пароля"})
			return
		}

		var result sql.Result
		if email != "" {
			encryptedEmail, encErr := encryptEmail(email)
			if encErr != nil {
				log.Println("Email encryption error:", encErr)
				render(w, "register.html", PageData{Title: "Регистрация", Error: "Ошибка обработки email"})
				return
			}
			result, err = db.Exec("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", username, encryptedEmail, string(hashedPassword))
		} else {
			result, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, string(hashedPassword))
		}
		if err != nil {
			if strings.Contains(err.Error(), "Duplicate entry") {
				render(w, "register.html", PageData{Title: "Регистрация", Error: "Пользователь уже существует"})
			} else {
				render(w, "register.html", PageData{Title: "Регистрация", Error: "Ошибка БД: " + err.Error()})
			}
			return
		}

		// Даём ачивку "Ранний пташка" новому пользователю
		newID, _ := result.LastInsertId()
		unlockAchievement(int(newID), "early_bird")

		// Отправляем письмо с подтверждением почты
		if email != "" {
			token, err := generateResetToken()
			if err == nil {
				// Сохраняем токен подтверждения (живёт 24 часа)
				db.Exec(
					"INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)",
					newID, "confirm_"+token, time.Now().Add(24*time.Hour),
				)

				// Отправляем письмо
				from := os.Getenv("SMTP_FROM")
				pass := os.Getenv("SMTP_PASS")
				smtpHost := os.Getenv("SMTP_HOST")
				smtpPort := os.Getenv("SMTP_PORT")
				if from != "" && pass != "" {
					confirmLink := fmt.Sprintf("http://localhost:8080/confirm-email?token=%s", "confirm_"+token)
					subject := "Subject: Подтверждение почты на AniMemory\r\n"
					mime := "MIME-version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n"
					body := fmt.Sprintf(`
						<h2>Подтверждение email</h2>
						<p>Спасибо за регистрацию на AniMemory!</p>
						<p>Перейдите по ссылке ниже, чтобы подтвердить свою почту:</p>
						<p><a href="%s">%s</a></p>
						<p>Ссылка действительна 24 часа.</p>
					`, confirmLink, confirmLink)
					headers := fmt.Sprintf("From: %s\r\nTo: %s\r\n", from, email)
					headers += "X-Priority: 3\r\nX-Mailer: AniMemory\r\n"
					fullMsg := []byte(headers + subject + mime + body)

					auth := smtp.PlainAuth("", from, pass, smtpHost)
					err = smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{email}, fullMsg)
					if err != nil {
						log.Printf("Confirm email send error: %v", err)
					}
				}
			}
		}

		render(w, "register.html", PageData{Title: "Регистрация", Success: "Регистрация успешна! На почту отправлено письмо для подтверждения."})
		return
	}
	render(w, "register.html", PageData{Title: "Регистрация"})
}

func animeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	idStr := strings.TrimPrefix(r.URL.Path, "/anime/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		notFoundHandler(w, r)
		return
	}

	var anime struct {
		ID          int
		Title       string
		Description string
		Poster      string
		Genres      string
		Year        string
		Country     string
		SourceType  string
		Studio      string
		Author      string
		Director    string
	}
	err = db.QueryRow("SELECT id, title, description, poster_url, genres, year, country, source_type, studio, author, director FROM anime WHERE id = ?", id).Scan(
		&anime.ID, &anime.Title, &anime.Description, &anime.Poster, &anime.Genres, &anime.Year,
		&anime.Country, &anime.SourceType, &anime.Studio, &anime.Author, &anime.Director)
	if err != nil {
		if err == sql.ErrNoRows {
			notFoundHandler(w, r)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	rows, err := db.Query("SELECT id, episode_num, season, title, poster_url FROM episodes WHERE anime_id = ? ORDER BY season, episode_num", id)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Episode struct {
		ID         int
		Num        int
		Season     int
		Title      string
		PosterURL  string
		IsFavorite bool
	}
	type SeasonGroup struct {
		Season   int
		Episodes []Episode
	}

	userID, _ := getUserIDFromSession(r)
	favoriteEpisodes := make(map[int]bool)
	if userID > 0 {
		feRows, err := db.Query(`
			SELECT fe.episode_id FROM favorite_episodes fe
			JOIN episodes e ON e.id = fe.episode_id
			WHERE fe.user_id = ? AND e.anime_id = ?
		`, userID, id)
		if err == nil {
			defer feRows.Close()
			for feRows.Next() {
				var epID int
				if feRows.Scan(&epID) == nil {
					favoriteEpisodes[epID] = true
				}
			}
		}
	}

	var seasons []SeasonGroup
	for rows.Next() {
		var ep Episode
		if err := rows.Scan(&ep.ID, &ep.Num, &ep.Season, &ep.Title, &ep.PosterURL); err != nil {
			continue
		}
		ep.IsFavorite = favoriteEpisodes[ep.ID]
		if len(seasons) == 0 || seasons[len(seasons)-1].Season != ep.Season {
			seasons = append(seasons, SeasonGroup{Season: ep.Season})
		}
		seasons[len(seasons)-1].Episodes = append(seasons[len(seasons)-1].Episodes, ep)
	}

	isAnimeFavorite := false
	if userID > 0 {
		var cnt int
		db.QueryRow("SELECT COUNT(*) FROM favorites WHERE user_id = ? AND anime_id = ?", userID, id).Scan(&cnt)
		isAnimeFavorite = cnt > 0
	}

	data := struct {
		Anime      interface{}
		Seasons    []SeasonGroup
		Username   string
		IsFavorite bool
	}{Anime: anime, Seasons: seasons, Username: currentUsername(r), IsFavorite: isAnimeFavorite}

	err = templates.ExecuteTemplate(w, "anime.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func watchHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	episodeIDStr := r.URL.Query().Get("episode")
	if episodeIDStr == "" {
		http.Error(w, "episode parameter required", http.StatusBadRequest)
		return
	}
	episodeID, err := strconv.Atoi(episodeIDStr)
	if err != nil {
		http.Error(w, "invalid episode id", http.StatusBadRequest)
		return
	}

	var episode struct {
		ID         int
		AnimeID    int
		EpisodeNum int
		Season     int
		Title      string
		VideoURL   string
		IntroStart sql.NullInt64
		IntroEnd   sql.NullInt64
		OutroStart sql.NullInt64
		OutroEnd   sql.NullInt64
	}
	err = db.QueryRow(`SELECT id, anime_id, episode_num, season, title, video_url,
		intro_start_sec, intro_end_sec, outro_start_sec, outro_end_sec
		FROM episodes WHERE id = ?`, episodeID).Scan(
		&episode.ID, &episode.AnimeID, &episode.EpisodeNum, &episode.Season, &episode.Title, &episode.VideoURL,
		&episode.IntroStart, &episode.IntroEnd, &episode.OutroStart, &episode.OutroEnd)
	if err != nil {
		if err == sql.ErrNoRows {
			notFoundHandler(w, r)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	// Получаем информацию об уровне пользователя для отображения
	userID, _ := getUserIDFromSession(r)
	levelInfo := UserLevelInfo{}
	chartColorID := ""
	if userID > 0 {
		var xp int
		err := db.QueryRow("SELECT xp FROM user_xp WHERE user_id = ?", userID).Scan(&xp)
		if err == nil {
			levelInfo = getLevelInfo(xp)
		}
		db.QueryRow("SELECT chart_color FROM users WHERE id = ?", userID).Scan(&chartColorID)
	}
	chartColor := chartColorPresets[0]
	if c, ok := chartColorByID(chartColorID); ok {
		chartColor = c
	}

	// Кнопки реакций с отметкой "разблокирована текущим уровнем" — эксклюзивные
	// анимированные смайлы (✨💯👑) показываются заблокированными ниже нужного уровня.
	type EmotionOption struct {
		emotionPreset
		Unlocked bool
	}
	emotionOptions := make([]EmotionOption, len(emotionPresets))
	for i, p := range emotionPresets {
		emotionOptions[i] = EmotionOption{emotionPreset: p, Unlocked: levelInfo.Level >= p.MinLevel}
	}

	var animeTitle string
	db.QueryRow("SELECT title FROM anime WHERE id = ?", episode.AnimeID).Scan(&animeTitle)

	// Следующие серии этого же сезона — показываем под блоком реакций/комментариев
	type NextEpisode struct {
		ID    int
		Num   int
		Title string
	}
	nextEpisodes := []NextEpisode{}
	epRows, err := db.Query(`SELECT id, episode_num, title FROM episodes
		WHERE anime_id = ? AND season = ? AND episode_num > ?
		ORDER BY episode_num LIMIT 8`, episode.AnimeID, episode.Season, episode.EpisodeNum)
	if err == nil {
		defer epRows.Close()
		for epRows.Next() {
			var ne NextEpisode
			if epRows.Scan(&ne.ID, &ne.Num, &ne.Title) == nil {
				nextEpisodes = append(nextEpisodes, ne)
			}
		}
	}

	// Соседние серии (в том же сезоне) для кнопок "Предыдущая"/"Следующая" в плеере
	var prevEpisodeID, nextEpisodeID int
	db.QueryRow(`SELECT id FROM episodes WHERE anime_id = ? AND season = ? AND episode_num < ?
		ORDER BY episode_num DESC LIMIT 1`, episode.AnimeID, episode.Season, episode.EpisodeNum).Scan(&prevEpisodeID)
	db.QueryRow(`SELECT id FROM episodes WHERE anime_id = ? AND season = ? AND episode_num > ?
		ORDER BY episode_num ASC LIMIT 1`, episode.AnimeID, episode.Season, episode.EpisodeNum).Scan(&nextEpisodeID)

	data := struct {
		EpisodeID     int
		EpisodeNum    int
		VideoURL      string
		Title         string
		UserLevel     UserLevelInfo
		Username      string
		IsPremium     bool
		AnimeID       int
		AnimeTitle    string
		PrevEpisodeID int
		NextEpisodeID int
		NextEpisodes  []NextEpisode
		// IntroStart/IntroEnd/OutroStart/OutroEnd: 0 здесь означает "не задано" (NULL в БД),
		// а не "начинается с 0-й секунды" — фронтенду нужно отдельно проверять,
		// заданы ли таймкоды (например, через ненулевой IntroEnd), прежде чем показывать кнопку "Пропустить".
		IntroStart      int64
		IntroEnd        int64
		OutroStart      int64
		OutroEnd        int64
		ChartColor      string
		ChartColorHover string
		EmotionOptions  []EmotionOption
	}{
		EpisodeID:       episode.ID,
		EpisodeNum:      episode.EpisodeNum,
		VideoURL:        episode.VideoURL,
		Title:           episode.Title,
		UserLevel:       levelInfo,
		Username:        currentUsername(r),
		IsPremium:       isPremiumUser(userID),
		AnimeID:         episode.AnimeID,
		AnimeTitle:      animeTitle,
		PrevEpisodeID:   prevEpisodeID,
		NextEpisodeID:   nextEpisodeID,
		NextEpisodes:    nextEpisodes,
		IntroStart:      episode.IntroStart.Int64,
		IntroEnd:        episode.IntroEnd.Int64,
		OutroStart:      episode.OutroStart.Int64,
		OutroEnd:        episode.OutroEnd.Int64,
		ChartColor:      chartColor.Color,
		ChartColorHover: chartColor.HoverColor,
		EmotionOptions:  emotionOptions,
	}

	err = templates.ExecuteTemplate(w, "watch.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	renderProfile(w, r, userID, userID)
}

// profileByUsernameHandler — публичный профиль /profile/{username}. Если он
// совпадает с профилем текущего пользователя, отдаём канонический /profile.
func profileByUsernameHandler(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/profile/")
	if username == "" {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	var targetID int
	if err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&targetID); err != nil {
		notFoundHandler(w, r)
		return
	}

	viewerID, _ := getUserIDFromSession(r)
	if viewerID == targetID {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}
	renderProfile(w, r, targetID, viewerID)
}

// renderProfile строит и рендерит страницу профиля targetID. viewerID — id
// текущего залогиненного пользователя (0, если гость); используется для
// определения статуса дружбы и того, свой ли это профиль.
func renderProfile(w http.ResponseWriter, r *http.Request, targetID, viewerID int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	isOwn := viewerID == targetID

	var username, avatarURL, avatarFrame, backgroundURL, chartColor, dmPrivacy string
	var isPremium, isBanned, showWatchingActivity bool
	err := db.QueryRow("SELECT username, avatar_url, avatar_frame, is_premium, background_url, is_banned, chart_color, show_watching_activity, dm_privacy FROM users WHERE id = ?", targetID).
		Scan(&username, &avatarURL, &avatarFrame, &isPremium, &backgroundURL, &isBanned, &chartColor, &showWatchingActivity, &dmPrivacy)
	if err != nil {
		notFoundHandler(w, r)
		return
	}

	// Username хедера — это залогиненный пользователь (viewer), а не владелец
	// просматриваемого профиля; header.html показывает по нему свой/гостевой вид.
	viewerUsername := ""
	if viewerID > 0 {
		if isOwn {
			viewerUsername = username
		} else {
			db.QueryRow("SELECT username FROM users WHERE id = ?", viewerID).Scan(&viewerUsername)
		}
	}

	// Получаем XP и уровень
	var xp int
	db.QueryRow("SELECT xp FROM user_xp WHERE user_id = ?", targetID).Scan(&xp)
	levelInfo := getLevelInfo(xp)

	avatarFrameColor := "#ffffff"
	if f, ok := avatarFrameByID(avatarFrame); ok && f.ID != "" {
		avatarFrameColor = f.Color
	}

	// Рамки аватара с отметкой "разблокирована текущим уровнем" — для селектора на странице
	type FrameOption struct {
		avatarFramePreset
		Unlocked bool
	}
	frameOptions := make([]FrameOption, len(avatarFramePresets))
	for i, f := range avatarFramePresets {
		frameOptions[i] = FrameOption{avatarFramePreset: f, Unlocked: levelInfo.Level >= f.MinLevel}
	}

	// Цвета графика реакций с отметкой "разблокирован текущим уровнем" — для селектора на странице
	type ChartColorOption struct {
		chartColorPreset
		Unlocked bool
	}
	chartColorOptions := make([]ChartColorOption, len(chartColorPresets))
	for i, c := range chartColorPresets {
		chartColorOptions[i] = ChartColorOption{chartColorPreset: c, Unlocked: levelInfo.Level >= c.MinLevel}
	}

	// Получаем ачивки
	userAchievements := getUserAchievements(targetID)

	// Полный каталог ачивок с отметкой "разблокирована" — для грида на странице
	// профиля (заблокированные показываем затемнёнными, а не просто скрываем)
	unlockedIDs := make(map[string]bool, len(userAchievements))
	for _, ua := range userAchievements {
		unlockedIDs[ua.AchievementID] = true
	}
	type AchievementSlot struct {
		Achievement
		Unlocked bool
	}
	achievementSlots := make([]AchievementSlot, len(achievements))
	for i, a := range achievements {
		achievementSlots[i] = AchievementSlot{Achievement: a, Unlocked: unlockedIDs[a.ID]}
	}

	// Получаем статистику
	var emotionCount, commentCount, episodeCount int
	db.QueryRow("SELECT COUNT(*) FROM emotions WHERE user_id = ?", targetID).Scan(&emotionCount)
	db.QueryRow("SELECT COUNT(*) FROM comments WHERE user_id = ?", targetID).Scan(&commentCount)
	db.QueryRow("SELECT COUNT(DISTINCT episode_id) FROM emotions WHERE user_id = ?", targetID).Scan(&episodeCount)

	// "Буду смотреть серию" — реальный прогресс просмотра (user_progress), последние 5.
	// Приватная информация — показываем только владельцу профиля.
	type ContinueEpisode struct {
		EpisodeID    int
		EpisodeNum   int
		EpisodeTitle string
		AnimeTitle   string
		Poster       string
		IsFavorite   bool // отмечен звёздочкой — можно убрать кнопкой "Удалить"
	}
	continueWatching := []ContinueEpisode{}
	// "Буду смотреть аниме" — избранные аниме пользователя
	type FavoriteAnime struct {
		AnimeID int
		Title   string
		Poster  string
	}
	favoriteAnime := []FavoriteAnime{}
	if isOwn {
		favoriteEpisodeIDs := make(map[int]bool)
		feIDRows, err := db.Query("SELECT episode_id FROM favorite_episodes WHERE user_id = ?", targetID)
		if err == nil {
			for feIDRows.Next() {
				var epID int
				if feIDRows.Scan(&epID) == nil {
					favoriteEpisodeIDs[epID] = true
				}
			}
			feIDRows.Close()
		}

		seenEpisodes := make(map[int]bool)
		cwRows, err := db.Query(`
			SELECT e.id, e.episode_num, e.title, a.title, a.poster_url
			FROM user_progress up
			JOIN episodes e ON up.episode_id = e.id
			JOIN anime a ON e.anime_id = a.id
			WHERE up.user_id = ?
			ORDER BY up.updated_at DESC
			LIMIT 5
		`, targetID)
		if err == nil {
			defer cwRows.Close()
			for cwRows.Next() {
				var ce ContinueEpisode
				if cwRows.Scan(&ce.EpisodeID, &ce.EpisodeNum, &ce.EpisodeTitle, &ce.AnimeTitle, &ce.Poster) == nil {
					ce.IsFavorite = favoriteEpisodeIDs[ce.EpisodeID]
					continueWatching = append(continueWatching, ce)
					seenEpisodes[ce.EpisodeID] = true
				}
			}
		}
		// Добавляем эпизоды, отмеченные звёздочкой "буду смотреть" на странице аниме,
		// но ещё не начатые (иначе они уже попали выше через user_progress).
		feRows, err := db.Query(`
			SELECT e.id, e.episode_num, e.title, a.title, a.poster_url
			FROM favorite_episodes fe
			JOIN episodes e ON e.id = fe.episode_id
			JOIN anime a ON e.anime_id = a.id
			WHERE fe.user_id = ?
			ORDER BY fe.created_at DESC
			LIMIT 8
		`, targetID)
		if err == nil {
			defer feRows.Close()
			for feRows.Next() {
				var ce ContinueEpisode
				if feRows.Scan(&ce.EpisodeID, &ce.EpisodeNum, &ce.EpisodeTitle, &ce.AnimeTitle, &ce.Poster) == nil && !seenEpisodes[ce.EpisodeID] {
					ce.IsFavorite = true
					continueWatching = append(continueWatching, ce)
					seenEpisodes[ce.EpisodeID] = true
				}
			}
		}

		faRows, err := db.Query(`
			SELECT a.id, a.title, a.poster_url
			FROM favorites f
			JOIN anime a ON a.id = f.anime_id
			WHERE f.user_id = ?
			ORDER BY f.created_at DESC
		`, targetID)
		if err == nil {
			defer faRows.Close()
			for faRows.Next() {
				var fa FavoriteAnime
				if faRows.Scan(&fa.AnimeID, &fa.Title, &fa.Poster) == nil {
					favoriteAnime = append(favoriteAnime, fa)
				}
			}
		}
	}

	friends := getFriends(targetID)
	var pendingRequests []FriendRequestInfo
	friendshipStatus := "self"
	friendshipRequestID := 0
	if !isOwn {
		friendshipStatus = getFriendshipStatus(viewerID, targetID)
		if friendshipStatus == "pending_received" {
			db.QueryRow("SELECT id FROM friendships WHERE requester_id = ? AND addressee_id = ?", targetID, viewerID).Scan(&friendshipRequestID)
		}
	} else {
		pendingRequests = getPendingIncoming(targetID)
	}

	data := struct {
		Username             string // виewer — для header.html
		ProfileUsername      string // владелец просматриваемого профиля
		ProfileUserID        int
		IsOwnProfile         bool
		FriendshipStatus     string
		FriendshipRequestID  int
		Friends              []FriendInfo
		PendingRequests      []FriendRequestInfo
		Level                UserLevelInfo
		AchievementSlots     []AchievementSlot
		EmotionCount         int
		CommentCount         int
		EpisodeCount         int
		ContinueWatching     []ContinueEpisode
		FavoriteAnime        []FavoriteAnime
		AvatarURL            string
		AvatarFrame          string
		AvatarFrameColor     string
		BackgroundURL        string
		IsPremium            bool
		FrameOptions         []FrameOption
		ChartColor           string
		ChartColorOptions    []ChartColorOption
		ShowWatchingActivity bool
		DmPrivacy            string
		IsViewerAdmin        bool
		IsBanned             bool
	}{
		Username:             viewerUsername,
		ProfileUsername:      username,
		ProfileUserID:        targetID,
		IsOwnProfile:         isOwn,
		FriendshipStatus:     friendshipStatus,
		FriendshipRequestID:  friendshipRequestID,
		Friends:              friends,
		PendingRequests:      pendingRequests,
		Level:                levelInfo,
		AchievementSlots:     achievementSlots,
		EmotionCount:         emotionCount,
		CommentCount:         commentCount,
		EpisodeCount:         episodeCount,
		ContinueWatching:     continueWatching,
		FavoriteAnime:        favoriteAnime,
		AvatarURL:            avatarURL,
		AvatarFrame:          avatarFrame,
		AvatarFrameColor:     avatarFrameColor,
		BackgroundURL:        backgroundURL,
		IsPremium:            isPremium,
		FrameOptions:         frameOptions,
		ChartColor:           chartColor,
		ChartColorOptions:    chartColorOptions,
		ShowWatchingActivity: showWatchingActivity,
		DmPrivacy:            dmPrivacy,
		IsViewerAdmin:        !isOwn && isUserAdmin(viewerID),
		IsBanned:             isBanned,
	}

	if err := templates.ExecuteTemplate(w, "profile.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// messagesHandler — GET /messages[?with=<user_id>]. Список диалогов +
// (опционально) предвыбранный собеседник — сама переписка грузится JS'ом.
func messagesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := getUserIDFromSession(r); err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	withID, _ := strconv.Atoi(r.URL.Query().Get("with"))
	withUsername := ""
	if withID > 0 {
		db.QueryRow("SELECT username FROM users WHERE id = ?", withID).Scan(&withUsername)
	}
	data := struct {
		Username     string
		WithUserID   int
		WithUsername string
	}{
		Username:     currentUsername(r),
		WithUserID:   withID,
		WithUsername: withUsername,
	}
	if err := templates.ExecuteTemplate(w, "messages.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func premiumHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	userID, _ := getUserIDFromSession(r)
	data := struct {
		Username  string
		IsPremium bool
	}{
		Username:  currentUsername(r),
		IsPremium: isPremiumUser(userID),
	}
	if err := templates.ExecuteTemplate(w, "premium.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func privacyPolicyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct{ Username string }{Username: currentUsername(r)}
	if err := templates.ExecuteTemplate(w, "privacy-policy.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func termsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct{ Username string }{Username: currentUsername(r)}
	if err := templates.ExecuteTemplate(w, "terms.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func apiEmotionPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		EpisodeID    int    `json:"episode_id"`
		TimestampSec int    `json:"timestamp_sec"`
		EmotionType  string `json:"emotion_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if req.EpisodeID == 0 || req.TimestampSec < 0 || req.EmotionType == "" {
		http.Error(w, `{"error":"Missing fields"}`, http.StatusBadRequest)
		return
	}
	preset, ok := emotionPresetByEmoji(req.EmotionType)
	if !ok {
		http.Error(w, `{"error":"Invalid emotion type"}`, http.StatusBadRequest)
		return
	}
	if userLevel(userID) < preset.MinLevel {
		http.Error(w, `{"error":"Эта реакция ещё не разблокирована — нужен более высокий уровень"}`, http.StatusForbidden)
		return
	}
	if !actionLimiter.allow(fmt.Sprintf("emotion:%d", userID), emotionRateLimit, emotionRateWindow) {
		http.Error(w, `{"error":"Слишком много реакций подряд, подождите немного"}`, http.StatusTooManyRequests)
		return
	}
	_, err = db.Exec("INSERT INTO emotions (user_id, episode_id, timestamp_sec, emotion_type) VALUES (?, ?, ?, ?)",
		userID, req.EpisodeID, req.TimestampSec, req.EmotionType)
	if err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}

	// Начисляем XP за эмоцию (с учётом анти-фарм лимита на эпизод)
	awardEmotionXP(userID, req.EpisodeID)
	newAchievements := checkAndUnlockAchievements(userID)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":                "ok",
		"unlocked_achievements": newAchievements,
	})
}

func apiEmotionsGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	episodeIDStr := r.URL.Query().Get("episode_id")
	if episodeIDStr == "" {
		http.Error(w, `{"error":"episode_id required"}`, http.StatusBadRequest)
		return
	}
	episodeID, _ := strconv.Atoi(episodeIDStr)

	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}
	pageSize := 50
	if ps, err := strconv.Atoi(r.URL.Query().Get("pageSize")); err == nil && ps > 0 && ps <= 200 {
		pageSize = ps
	}
	offset := (page - 1) * pageSize

	userID, _ := getUserIDFromSession(r)
	friendIDs := make(map[int]bool)
	if userID > 0 {
		for _, f := range getFriends(userID) {
			friendIDs[f.UserID] = true
		}
	}
	query := `
		SELECT e.emotion_type, e.timestamp_sec, u.username, e.user_id, COALESCE(ux.xp, 0)
		FROM emotions e
		JOIN users u ON e.user_id = u.id
		LEFT JOIN user_xp ux ON ux.user_id = u.id
		WHERE e.episode_id = ?`
	args := []interface{}{episodeID}
	if !isPremiumUser(userID) {
		query += " AND e.timestamp_sec <= ?"
		args = append(args, watchedUpToSec(userID, episodeID))
	}
	query += " ORDER BY e.timestamp_sec ASC LIMIT ? OFFSET ?"
	args = append(args, pageSize, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Emotion struct {
		EmotionType  string `json:"emotion_type"`
		TimestampSec int    `json:"timestamp_sec"`
		Username     string `json:"username"`
		IsFriend     bool   `json:"is_friend"`
		Badge        string `json:"badge"`
	}
	emotions := []Emotion{}
	for rows.Next() {
		var e Emotion
		var authorID, xp int
		if err := rows.Scan(&e.EmotionType, &e.TimestampSec, &e.Username, &authorID, &xp); err != nil {
			continue
		}
		e.IsFriend = friendIDs[authorID]
		e.Badge = levelBadge(getLevelInfo(xp).Level)
		emotions = append(emotions, e)
	}

	json.NewEncoder(w).Encode(emotions)
}

func apiChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Не авторизован"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request"}`, http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < 8 {
		http.Error(w, `{"error":"Новый пароль должен быть не короче 8 символов"}`, http.StatusBadRequest)
		return
	}
	if req.NewPassword == req.OldPassword {
		http.Error(w, `{"error":"Новый пароль должен отличаться от старого"}`, http.StatusBadRequest)
		return
	}

	var currentHash string
	if err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&currentHash); err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.OldPassword)); err != nil {
		http.Error(w, `{"error":"Неверный текущий пароль"}`, http.StatusUnauthorized)
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcryptCost)
	if err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	if _, err := db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(newHash), userID); err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, `{"status":"ok"}`)
}

// apiUserDeleteHandler — POST /api/user/delete: право на удаление персональных
// данных (GDPR/152-ФЗ). Требует подтверждения текущим паролем — необратимая
// операция, одной валидной сессии для неё недостаточно. Удаляет пользователя
// и все данные, ссылающиеся на него по user_id, одной транзакцией.
func apiUserDeleteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Не авторизован"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request"}`, http.StatusBadRequest)
		return
	}

	var currentHash string
	if err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&currentHash); err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.Password)); err != nil {
		http.Error(w, `{"error":"Неверный пароль"}`, http.StatusUnauthorized)
		return
	}

	if err := deleteUserData(userID); err != nil {
		log.Println("apiUserDeleteHandler:", err)
		http.Error(w, `{"error":"Ошибка удаления данных"}`, http.StatusInternalServerError)
		return
	}

	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	clearAuthCookies(w, secure)
	session, _ := store.Get(r, "ancen-session")
	session.Options = &sessions.Options{Path: "/", MaxAge: -1}
	session.Save(r, w)

	fmt.Fprint(w, `{"status":"ok"}`)
}

// deleteUserData удаляет пользователя и все зависящие от него по user_id
// записи одной транзакцией — таблицы без ON DELETE CASCADE иначе оставили бы
// висячие ссылки.
func deleteUserData(userID int) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tables := []string{
		"emotions", "comments", "user_xp", "user_xp_daily",
		"user_achievements", "user_progress", "password_resets", "refresh_tokens",
	}
	for _, table := range tables {
		if _, err := tx.Exec("DELETE FROM "+table+" WHERE user_id = ?", userID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec("DELETE FROM users WHERE id = ?", userID); err != nil {
		return err
	}
	return tx.Commit()
}

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	// Разрешаем апгрейд только с того же хоста, что и сам сервер (защита от
	// Cross-Site WebSocket Hijacking: без этой проверки чужой сайт мог бы
	// открыть WS-соединение от имени залогиненного пользователя, используя
	// его cookie, которую браузер прикрепляет автоматически).
	CheckOrigin: sameOrigin,
}

// sameOrigin сверяет заголовок Origin запроса с хостом сервера — общая проверка
// для WS-апгрейда (защита от CSWSH) и для CSRF-мидлвары мутирующих HTTP-запросов.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Запрос не от браузера (нет Origin) — например, curl/wscat при разработке,
		// или старый браузер, не проставляющий Origin на same-site POST
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

// Сообщение от клиента
type WsMessage struct {
	Type         string `json:"type"`
	EpisodeID    int    `json:"episode_id"`
	TimestampSec int    `json:"timestamp_sec"`
	EmotionType  string `json:"emotion_type"`
	Username     string `json:"username"`
	UserID       int    `json:"user_id,omitempty"`
	Badge        string `json:"badge,omitempty"`

	// Синхропросмотр (party_* / rtc_* / player_sync) — см. PartyHub ниже.
	PartyID      string  `json:"party_id,omitempty"`
	TargetUserID int     `json:"target_user_id,omitempty"`
	SDP          string  `json:"sdp,omitempty"`
	Candidate    string  `json:"candidate,omitempty"` // JSON-строка ICE-кандидата, сервер не парсит содержимое
	PlaybackSec  float64 `json:"playback_sec,omitempty"`
	Paused       bool    `json:"paused,omitempty"`
	Reason       string  `json:"reason,omitempty"` // party_invite_failed: "not_friend" | "offline"
}

// Клиент
type Client struct {
	conn      *websocket.Conn
	send      chan []byte
	episodeID int
	userID    int
	friendIDs map[int]bool // друзья зрителя — для подсветки их реакций в его собственной ленте
}

// Hub (управляет комнатами)
type Hub struct {
	rooms      map[int]map[*Client]bool
	byUser     map[int]*Client // последнее активное соединение пользователя — адресная маршрутизация для синхропросмотра (party_*/rtc_*)
	register   chan *Client
	unregister chan *Client
	broadcast  chan WsMessage
	mu         sync.RWMutex
}

var hub = &Hub{
	rooms:      make(map[int]map[*Client]bool),
	byUser:     make(map[int]*Client),
	register:   make(chan *Client),
	unregister: make(chan *Client),
	broadcast:  make(chan WsMessage),
}

// clientByUser возвращает текущее WS-соединение пользователя (если он сейчас
// на watch.html), для адресной отправки сигналинга — не бродкаста всей
// комнате эпизода, как обычные реакции.
func (h *Hub) clientByUser(userID int) *Client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.byUser[userID]
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			if _, ok := h.rooms[client.episodeID]; !ok {
				h.rooms[client.episodeID] = make(map[*Client]bool)
			}
			h.rooms[client.episodeID][client] = true
			h.byUser[client.userID] = client
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if clients, ok := h.rooms[client.episodeID]; ok {
				delete(clients, client)
				if len(clients) == 0 {
					delete(h.rooms, client.episodeID)
				}
			}
			if h.byUser[client.userID] == client {
				delete(h.byUser, client.userID)
			}
			h.mu.Unlock()
			close(client.send)

		case msg := <-h.broadcast:
			h.mu.RLock()
			clients := h.rooms[msg.EpisodeID]
			h.mu.RUnlock()

			// is_friend зависит от того, КТО смотрит, а не от самого сообщения —
			// поэтому шлём каждому клиенту отдельно промаршаленный вариант, а не
			// один общий payload на всю комнату.
			for client := range clients {
				out := struct {
					WsMessage
					IsFriend bool `json:"is_friend"`
				}{WsMessage: msg, IsFriend: client.friendIDs[msg.UserID]}
				data, _ := json.Marshal(out)
				select {
				case client.send <- data:
				default:
					close(client.send)
					h.unregister <- client
				}
			}
		}
	}
}

// WebSocket endpoint
func wsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("🔥 wsHandler вызван")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		log.Println("Unauthorized ws connection:", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	episodeIDStr := r.URL.Query().Get("episode_id")
	episodeID, err := strconv.Atoi(episodeIDStr)
	if err != nil || episodeID == 0 {
		http.Error(w, "episode_id required", http.StatusBadRequest)
		return
	}

	var username string
	err = db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade error:", err)
		return
	}
	log.Println("WebSocket upgraded successfully")
	friendIDs := make(map[int]bool)
	for _, f := range getFriends(userID) {
		friendIDs[f.UserID] = true
	}
	client := &Client{
		conn:      conn,
		send:      make(chan []byte, 256),
		episodeID: episodeID,
		userID:    userID,
		friendIDs: friendIDs,
	}
	hub.register <- client

	go func() {
		log.Println("🚀 reader goroutine started")
		defer func() {
			hub.unregister <- client
			conn.Close()
			// Отключение по любой причине (закрыл вкладку, упал коннект) должно
			// закрывать и звонок синхропросмотра — иначе второй участник
			// зависает в party с молчащим собеседником навсегда.
			if partyID, remaining := partyH.leave(userID); partyID != "" {
				for _, uid := range remaining {
					sendToUser(uid, WsMessage{Type: "party_left", PartyID: partyID, UserID: userID})
				}
			}
		}()
		for {
			var msg WsMessage
			err := conn.ReadJSON(&msg)
			if err != nil {
				log.Println("ReadJSON error:", err)
				break
			}
			log.Printf("📨 Received WS message: type=%s episode_id=%d emotion_type=%s", msg.Type, msg.EpisodeID, msg.EmotionType)
			switch msg.Type {
			case "party_invite", "party_accept", "party_decline", "party_leave", "rtc_offer", "rtc_answer", "rtc_ice", "player_sync":
				handlePartyMessage(msg, userID, username)
				continue
			}
			if msg.Type == "emotion" && msg.EpisodeID == episodeID {
				preset, ok := emotionPresetByEmoji(msg.EmotionType)
				if !ok || msg.TimestampSec < 0 {
					continue
				}
				if userLevel(userID) < preset.MinLevel {
					continue
				}
				if !actionLimiter.allow(fmt.Sprintf("emotion:%d", userID), emotionRateLimit, emotionRateWindow) {
					continue
				}
				_, err = db.Exec("INSERT INTO emotions (user_id, episode_id, timestamp_sec, emotion_type) VALUES (?, ?, ?, ?)",
					userID, msg.EpisodeID, msg.TimestampSec, msg.EmotionType)
				if err != nil {
					log.Println("DB error:", err)
					continue
				}
				msg.Username = username
				msg.UserID = userID
				msg.Badge = levelBadge(userLevel(userID))
				hub.broadcast <- msg

				// Начисляем XP за эмоцию через WebSocket (с учётом анти-фарм лимита на эпизод)
				awardEmotionXP(userID, msg.EpisodeID)
				if newAchievements := checkAndUnlockAchievements(userID); len(newAchievements) > 0 {
					// Личное уведомление только отправителю, не всей комнате
					if data, err := json.Marshal(map[string]interface{}{
						"type":         "achievement_unlocked",
						"achievements": newAchievements,
					}); err == nil {
						select {
						case client.send <- data:
						default:
						}
					}
				}
			}
		}
	}()

	go func() {
		for data := range client.send {
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				break
			}
		}
	}()
}

// ===== Синхропросмотр: party-хаб =====
//
// Party — сессия из двух друзей, смотрящих один эпизод синхронно (голосовой
// звонок + общий play/pause/seek). Комнаты обычного Hub адресуются по
// episodeID и включают вообще всех зрителей серии — для party нужна
// отдельная группа из только приглашённых участников, живущая в памяти
// ровно на время звонка (не в БД — как только оба вышли, сессия не нужна).
type party struct {
	episodeID int
	hostID    int
	members   map[int]bool
}

type partyHub struct {
	mu       sync.Mutex
	parties  map[string]*party
	byMember map[int]string // userID -> partyID, для быстрого lookup при leave/disconnect
}

var partyH = &partyHub{
	parties:  make(map[string]*party),
	byMember: make(map[int]string),
}

// create создаёт новую party с единственным участником — хостом (тем, кто
// приглашает). Второй участник добавляется через join после party_accept.
func (p *partyHub) create(episodeID, hostID int) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := fmt.Sprintf("party-%d-%d", hostID, time.Now().UnixNano())
	p.parties[id] = &party{episodeID: episodeID, hostID: hostID, members: map[int]bool{hostID: true}}
	p.byMember[hostID] = id
	return id
}

// join добавляет пользователя в party при party_accept. Отказывает, если
// party не существует (протухла/отменена) — вызывающий код должен сообщить
// об этом отправителю.
func (p *partyHub) join(partyID string, userID int) (*party, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pt, ok := p.parties[partyID]
	if !ok {
		return nil, false
	}
	pt.members[userID] = true
	p.byMember[userID] = partyID
	return pt, true
}

// isMember проверяет принадлежность до маршрутизации rtc_*/player_sync —
// чтобы один пользователь не мог слать сигналинг в чужую party, зная её id.
func (p *partyHub) isMember(partyID string, userID int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	pt, ok := p.parties[partyID]
	return ok && pt.members[userID]
}

// hostOf — кто позвал (для REST-отклонения приглашения из шапки: декланер
// сам ещё не член party, поэтому isMember тут не подходит).
func (p *partyHub) hostOf(partyID string) (int, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pt, ok := p.parties[partyID]
	if !ok {
		return 0, false
	}
	return pt.hostID, true
}

// otherMembers возвращает остальных участников party (для рассылки
// player_sync — событие плеера долетает до всех, кроме отправителя).
func (p *partyHub) otherMembers(partyID string, exceptUserID int) []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	pt, ok := p.parties[partyID]
	if !ok {
		return nil
	}
	var others []int
	for uid := range pt.members {
		if uid != exceptUserID {
			others = append(others, uid)
		}
	}
	return others
}

// leave убирает участника; если party опустела — удаляет её целиком.
// Возвращает id party и оставшихся участников (чтобы уведомить их о выходе).
// cancel удаляет party целиком по id, независимо от состава участников —
// используется при отклонении приглашения, когда party так и не была
// присоединена вторым участником (leave по userID тут не подходит: у
// party_decline отправитель — не хост, а тот, кого позвали и кто в party
// ещё не значится как member).
func (p *partyHub) cancel(partyID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pt, ok := p.parties[partyID]
	if !ok {
		return
	}
	for uid := range pt.members {
		if p.byMember[uid] == partyID {
			delete(p.byMember, uid)
		}
	}
	delete(p.parties, partyID)
}

func (p *partyHub) leave(userID int) (partyID string, remaining []int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	partyID, ok := p.byMember[userID]
	if !ok {
		return "", nil
	}
	delete(p.byMember, userID)
	pt, ok := p.parties[partyID]
	if !ok {
		return partyID, nil
	}
	delete(pt.members, userID)
	if len(pt.members) == 0 {
		delete(p.parties, partyID)
		return partyID, nil
	}
	for uid := range pt.members {
		remaining = append(remaining, uid)
	}
	return partyID, remaining
}

// sendToUser маршалит WsMessage и кладёт его в send-канал конкретного
// пользователя, если он сейчас подключён — не бродкаст, адресная доставка.
// sendToUser возвращает true, если сообщение реально поставлено в очередь
// отправки — вызывающий код (party_invite) использует это, чтобы сразу
// сказать пригласившему "друг сейчас не на сайте", а не молча промолчать.
func sendToUser(userID int, msg WsMessage) bool {
	client := hub.clientByUser(userID)
	if client == nil {
		return false
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return false
	}
	select {
	case client.send <- data:
		return true
	default:
		return false
	}
}

// pushToUser — как sendToUser, но через dmHub (глобальный push по user_id,
// не привязан к тому, на watch.html ли получатель прямо сейчас). Нужен для
// party_invite: приглашённый друг может быть где угодно на сайте, а не
// обязательно на той же серии — episode-scoped hub его бы не нашёл.
func pushToUser(userID int, msg WsMessage) bool {
	data, err := json.Marshal(msg)
	if err != nil {
		return false
	}
	return dmh.push(userID, data)
}

// handlePartyMessage обрабатывает party_*/rtc_*/player_sync сообщения из
// wsHandler. senderID/senderUsername — уже проверенная личность отправителя
// (сессия проверена выше в wsHandler, здесь просто диспетчер по типу).
func handlePartyMessage(msg WsMessage, senderID int, senderUsername string) {
	switch msg.Type {
	case "party_invite":
		// Приглашать можно только друга — переиспользуем уже посчитанный
		// при коннекте client.friendIDs было бы удобнее, но handlePartyMessage
		// не имеет доступа к конкретному *Client отправителя, поэтому здесь
		// достаточно того же источника истины (таблица friendships).
		isFriend := false
		for _, f := range getFriends(senderID) {
			if f.UserID == msg.TargetUserID {
				isFriend = true
				break
			}
		}
		if !isFriend || msg.TargetUserID == senderID {
			sendToUser(senderID, WsMessage{Type: "party_invite_failed", TargetUserID: msg.TargetUserID, Reason: "not_friend"})
			return
		}
		partyID := partyH.create(msg.EpisodeID, senderID)
		// pushToUser (dmHub), не sendToUser (episode-hub) — друга приглашают
		// откуда угодно на сайте, он не обязан быть на watch.html этой серии.
		delivered := pushToUser(msg.TargetUserID, WsMessage{
			Type:      "party_invite",
			PartyID:   partyID,
			EpisodeID: msg.EpisodeID,
			UserID:    senderID,
			Username:  senderUsername,
		})
		if !delivered {
			// Друг реально не в сети (ни одной открытой вкладки сайта) — раньше
			// это молча терялось: приглашающий видел "Приглашение отправлено" и
			// ждал ответа, которого никогда не будет.
			partyH.cancel(partyID)
			sendToUser(senderID, WsMessage{Type: "party_invite_failed", TargetUserID: msg.TargetUserID, Reason: "offline"})
		}

	case "party_accept":
		pt, ok := partyH.join(msg.PartyID, senderID)
		if !ok {
			sendToUser(senderID, WsMessage{Type: "party_expired", PartyID: msg.PartyID})
			return
		}
		// Уведомляем всех членов party (включая хоста), что участник
		// присоединился — на фронте это сигнал начинать WebRTC-хендшейк.
		for uid := range pt.members {
			sendToUser(uid, WsMessage{
				Type:      "party_joined",
				PartyID:   msg.PartyID,
				EpisodeID: pt.episodeID,
				UserID:    senderID,
				Username:  senderUsername,
			})
		}

	case "party_decline":
		sendToUser(msg.TargetUserID, WsMessage{Type: "party_declined", PartyID: msg.PartyID, UserID: senderID})
		partyH.cancel(msg.PartyID)

	case "party_leave":
		partyID, remaining := partyH.leave(senderID)
		for _, uid := range remaining {
			sendToUser(uid, WsMessage{Type: "party_left", PartyID: partyID, UserID: senderID})
		}

	case "rtc_offer", "rtc_answer", "rtc_ice":
		if !partyH.isMember(msg.PartyID, senderID) || !partyH.isMember(msg.PartyID, msg.TargetUserID) {
			return
		}
		msg.UserID = senderID
		sendToUser(msg.TargetUserID, msg)

	case "player_sync":
		if !partyH.isMember(msg.PartyID, senderID) {
			return
		}
		for _, uid := range partyH.otherMembers(msg.PartyID, senderID) {
			sendToUser(uid, WsMessage{
				Type:        "player_sync",
				PartyID:     msg.PartyID,
				PlaybackSec: msg.PlaybackSec,
				Paused:      msg.Paused,
				UserID:      senderID,
			})
		}
	}
}

// ===== Личные сообщения: отдельный WS-хаб по user_id =====
//
// Комнатный hub выше адресует по episodeID (все зрители одной серии видят
// одно и то же). Для личных сообщений между произвольными парами
// пользователей это не подходит — нужен канал на каждого конкретного
// получателя, а не на комнату. dmHub — push-only: клиент открывает
// соединение просто чтобы получать новые сообщения в реальном времени,
// сама отправка идёт через REST (apiMessageSend), не через сокет — это
// не создаёт новых проблем синхронизации с тем, что уже пишется в БД.
type dmHub struct {
	mu      sync.RWMutex
	clients map[int]map[*websocket.Conn]bool
}

var dmh = &dmHub{clients: make(map[int]map[*websocket.Conn]bool)}

func (h *dmHub) register(userID int, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients[userID] == nil {
		h.clients[userID] = make(map[*websocket.Conn]bool)
	}
	h.clients[userID][conn] = true
}

func (h *dmHub) unregister(userID int, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if conns, ok := h.clients[userID]; ok {
		delete(conns, conn)
		if len(conns) == 0 {
			delete(h.clients, userID)
		}
	}
}

// push возвращает true, только если запись хотя бы в одно соединение
// получателя реально прошла без ошибки — используется приглашением в party,
// чтобы понять, дошло ли оно вообще (пользователь может быть просто не в
// сети, а не только не на этой странице). Раньше ошибка WriteMessage
// игнорировалась и delivered ставился в true по одному факту наличия
// соединения в мапе — если вкладка друга зависла/уснула и TCP-соединение
// стало "мёртвым" без явного close, push всё равно рапортовал успех, и
// приглашение молча терялось без "оффлайн"-уведомления отправителю.
func (h *dmHub) push(userID int, data []byte) bool {
	h.mu.RLock()
	conns := make([]*websocket.Conn, 0, len(h.clients[userID]))
	for conn := range h.clients[userID] {
		conns = append(conns, conn)
	}
	h.mu.RUnlock()

	delivered := false
	var dead []*websocket.Conn
	for _, conn := range conns {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			dead = append(dead, conn)
			continue
		}
		delivered = true
	}
	if len(dead) > 0 {
		h.mu.Lock()
		for _, conn := range dead {
			if conns, ok := h.clients[userID]; ok {
				delete(conns, conn)
				if len(conns) == 0 {
					delete(h.clients, userID)
				}
			}
			conn.Close()
		}
		h.mu.Unlock()
	}
	return delivered
}

// wsDMHandler — /ws/dm. Открывается один раз при заходе на сайт (не привязан
// к конкретному диалогу), держит соединение открытым для push новых
// сообщений и обновления бейджа непрочитанных.
func wsDMHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("dm upgrade error:", err)
		return
	}
	dmh.register(userID, conn)
	defer func() {
		dmh.unregister(userID, conn)
		conn.Close()
	}()
	// Читаем только чтобы обнаружить закрытие соединения — клиент по этому
	// сокету ничего не отправляет, вся отправка идёт через REST.
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

// Message — одно личное сообщение в переписке.
type Message struct {
	ID          int    `json:"id"`
	SenderID    int    `json:"sender_id"`
	RecipientID int    `json:"recipient_id"`
	SenderName  string `json:"sender_username"`
	Text        string `json:"text"`
	CreatedAt   string `json:"created_at"`
	IsRead      bool   `json:"is_read"`
}

// canMessage проверяет, может ли senderID написать recipientID — учитывает
// dm_privacy получателя (Premium-фича, см. 18_Монетизация_и_уровни.md).
// Значение 'friends_only' у получателя без Premium игнорируется — форсим
// 'everyone', чтобы отключение подписки не оставляло зависший приватный
// режим по старому значению в БД.
func canMessage(senderID, recipientID int) bool {
	if senderID == recipientID {
		return false
	}
	var privacy string
	var recipientIsPremium bool
	if err := db.QueryRow("SELECT dm_privacy, is_premium FROM users WHERE id = ?", recipientID).Scan(&privacy, &recipientIsPremium); err != nil {
		return false
	}
	if !recipientIsPremium || privacy != "friends_only" {
		return true
	}
	return getFriendshipStatus(senderID, recipientID) == "friends"
}

// apiMessagesGet — GET /api/messages?with=<user_id>&page=&pageSize= — история
// переписки с конкретным собеседником, накопительная пагинация как у
// комментариев/эмоций.
func apiMessagesGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	withID, _ := strconv.Atoi(r.URL.Query().Get("with"))
	if withID == 0 {
		http.Error(w, `{"error":"with required"}`, http.StatusBadRequest)
		return
	}

	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}
	pageSize := 30
	if ps, err := strconv.Atoi(r.URL.Query().Get("pageSize")); err == nil && ps > 0 && ps <= 100 {
		pageSize = ps
	}
	offset := (page - 1) * pageSize

	rows, err := db.Query(`
		SELECT m.id, m.sender_id, m.recipient_id, u.username, m.text, m.created_at, m.read_at
		FROM messages m
		JOIN users u ON u.id = m.sender_id
		WHERE (m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?)
		ORDER BY m.created_at DESC LIMIT ? OFFSET ?
	`, userID, withID, withID, userID, pageSize, offset)
	if err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	messages := []Message{}
	for rows.Next() {
		var m Message
		var createdAt, readAt sql.NullTime
		if err := rows.Scan(&m.ID, &m.SenderID, &m.RecipientID, &m.SenderName, &m.Text, &createdAt, &readAt); err != nil {
			continue
		}
		if createdAt.Valid {
			m.CreatedAt = createdAt.Time.Format("2006-01-02 15:04:05")
		}
		// Свои же отправленные сообщения нечего "читать по наведению" —
		// непрочитанным для UI считается только чужое входящее.
		m.IsRead = readAt.Valid || m.SenderID == userID
		messages = append(messages, m)
	}
	json.NewEncoder(w).Encode(messages)
}

// apiMessageSend — POST /api/messages/send {recipient_id, text}.
func apiMessageSend(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		RecipientID int    `json:"recipient_id"`
		Text        string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RecipientID == 0 || strings.TrimSpace(req.Text) == "" {
		http.Error(w, `{"error":"recipient_id и text обязательны"}`, http.StatusBadRequest)
		return
	}
	if !actionLimiter.allow(fmt.Sprintf("message:%d", userID), messageRateLimit, messageRateWindow) {
		http.Error(w, `{"error":"Слишком много сообщений подряд, подождите немного"}`, http.StatusTooManyRequests)
		return
	}
	if !canMessage(userID, req.RecipientID) {
		http.Error(w, `{"error":"Этот пользователь принимает сообщения только от друзей"}`, http.StatusForbidden)
		return
	}

	text := req.Text
	if len(text) > 1000 {
		text = text[:1000]
	}
	text = strings.ReplaceAll(text, "<", "&lt;")
	text = strings.ReplaceAll(text, ">", "&gt;")

	res, err := db.Exec("INSERT INTO messages (sender_id, recipient_id, text) VALUES (?, ?, ?)", userID, req.RecipientID, text)
	if err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	msgID, _ := res.LastInsertId()

	msg := Message{
		ID:          int(msgID),
		SenderID:    userID,
		RecipientID: req.RecipientID,
		SenderName:  currentUsername(r),
		Text:        text,
		CreatedAt:   time.Now().Format("2006-01-02 15:04:05"),
	}
	if data, err := json.Marshal(map[string]interface{}{"type": "dm", "message": msg}); err == nil {
		dmh.push(req.RecipientID, data)
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(msg)
}

// Conversation — одна строка списка диалогов на /messages.
type Conversation struct {
	UserID      int    `json:"user_id"`
	Username    string `json:"username"`
	AvatarURL   string `json:"avatar_url"`
	LastText    string `json:"last_text"`
	LastAt      string `json:"last_at"`
	UnreadCount int    `json:"unread_count"`
}

// apiConversationsList — GET /api/conversations — список диалогов с
// последним сообщением и числом непрочитанных, отсортирован по свежести.
func apiConversationsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Собеседник — тот, кто не я, в каждой паре, где я участвую.
	rows, err := db.Query(`
		SELECT peer_id FROM (
			SELECT sender_id AS peer_id FROM messages WHERE recipient_id = ?
			UNION
			SELECT recipient_id AS peer_id FROM messages WHERE sender_id = ?
		) peers
	`, userID, userID)
	if err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	var peerIDs []int
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			peerIDs = append(peerIDs, id)
		}
	}
	rows.Close()

	conversations := make([]Conversation, 0, len(peerIDs))
	for _, peerID := range peerIDs {
		var c Conversation
		c.UserID = peerID
		db.QueryRow("SELECT username, avatar_url FROM users WHERE id = ?", peerID).Scan(&c.Username, &c.AvatarURL)

		var lastAt sql.NullTime
		db.QueryRow(`
			SELECT text, created_at FROM messages
			WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
			ORDER BY created_at DESC LIMIT 1
		`, userID, peerID, peerID, userID).Scan(&c.LastText, &lastAt)
		if lastAt.Valid {
			c.LastAt = lastAt.Time.Format("2006-01-02 15:04:05")
		}

		db.QueryRow("SELECT COUNT(*) FROM messages WHERE sender_id = ? AND recipient_id = ? AND read_at IS NULL", peerID, userID).Scan(&c.UnreadCount)

		conversations = append(conversations, c)
	}
	sort.Slice(conversations, func(i, j int) bool { return conversations[i].LastAt > conversations[j].LastAt })

	json.NewEncoder(w).Encode(conversations)
}

// apiMessagesMarkRead — POST /api/messages/read {with: user_id}.
func apiMessagesMarkRead(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		With int `json:"with"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.With == 0 {
		http.Error(w, `{"error":"with required"}`, http.StatusBadRequest)
		return
	}
	if _, err := db.Exec("UPDATE messages SET read_at = NOW() WHERE sender_id = ? AND recipient_id = ? AND read_at IS NULL", req.With, userID); err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// apiMessageReadOne — POST /api/messages/read-one {message_id} — помечает
// прочитанным ровно одно сообщение (наведение на конкретную реплику в
// открытом диалоге), в отличие от apiMessagesReadHandler выше, который
// разом закрывает всю переписку с собеседником.
func apiMessageReadOne(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		MessageID int `json:"message_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MessageID == 0 {
		http.Error(w, `{"error":"message_id required"}`, http.StatusBadRequest)
		return
	}
	if _, err := db.Exec("UPDATE messages SET read_at = NOW() WHERE id = ? AND recipient_id = ? AND read_at IS NULL", req.MessageID, userID); err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// apiUnreadMessagesCount — GET /api/messages/unread-count — для бейджа в хедере.
func apiUnreadMessagesCount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND read_at IS NULL", userID).Scan(&count)
	json.NewEncoder(w).Encode(map[string]int{"count": count})
}

// apiDmPrivacyToggle — POST /api/profile/dm-privacy {privacy: "everyone"|"friends_only"}.
// friends_only доступно только Premium — см. canMessage.
func apiDmPrivacyToggle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		Privacy string `json:"privacy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Privacy != "everyone" && req.Privacy != "friends_only") {
		http.Error(w, `{"error":"privacy должен быть everyone или friends_only"}`, http.StatusBadRequest)
		return
	}
	if req.Privacy == "friends_only" && !isPremiumUser(userID) {
		http.Error(w, `{"error":"Ограничение до друзей доступно только по подписке Premium"}`, http.StatusForbidden)
		return
	}
	if _, err := db.Exec("UPDATE users SET dm_privacy = ? WHERE id = ?", req.Privacy, userID); err != nil {
		http.Error(w, `{"error":"Ошибка сохранения"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func apiEmotionsStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	episodeIDStr := r.URL.Query().Get("episode_id")
	if episodeIDStr == "" {
		http.Error(w, `{"error":"episode_id required"}`, http.StatusBadRequest)
		return
	}
	episodeID, err := strconv.Atoi(episodeIDStr)
	if err != nil {
		http.Error(w, `{"error":"invalid episode_id"}`, http.StatusBadRequest)
		return
	}

	interval := 10

	rows, err := db.Query(`
		SELECT 
			FLOOR(timestamp_sec / ?) * ? AS interval_start,
			COUNT(*) as cnt
		FROM emotions
		WHERE episode_id = ?
		GROUP BY interval_start
		ORDER BY interval_start ASC
	`, interval, interval, episodeID)
	if err != nil {
		http.Error(w, `{"error":"DB error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Stat struct {
		IntervalStart int `json:"interval_start"`
		Count         int `json:"count"`
	}
	stats := []Stat{}
	for rows.Next() {
		var start int
		var cnt int
		if err := rows.Scan(&start, &cnt); err != nil {
			continue
		}
		stats = append(stats, Stat{IntervalStart: start, Count: cnt})
	}
	json.NewEncoder(w).Encode(stats)
}

type Comment struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	TimestampSec int    `json:"timestamp_sec"`
	Text         string `json:"text"`
	AudioURL     string `json:"audio_url,omitempty"`
	CreatedAt    string `json:"created_at"`
	LikeCount    int    `json:"like_count"`
	LikedByMe    bool   `json:"liked_by_me"`
	Badge        string `json:"badge"`
	Color        string `json:"color"`
}

func apiCommentPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		EpisodeID    int    `json:"episode_id"`
		TimestampSec int    `json:"timestamp_sec"`
		Text         string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if req.EpisodeID == 0 || req.Text == "" {
		http.Error(w, `{"error":"Missing fields"}`, http.StatusBadRequest)
		return
	}
	if !actionLimiter.allow(fmt.Sprintf("comment:%d", userID), commentRateLimit, commentRateWindow) {
		http.Error(w, `{"error":"Слишком много комментариев подряд, подождите немного"}`, http.StatusTooManyRequests)
		return
	}
	// Ограничение длины комментария
	if len(req.Text) > 500 {
		req.Text = req.Text[:500]
	}
	// Замена HTML-тегов для защиты от XSS
	req.Text = strings.ReplaceAll(req.Text, "<", "<")
	req.Text = strings.ReplaceAll(req.Text, ">", ">")

	_, err = db.Exec("INSERT INTO comments (user_id, episode_id, timestamp_sec, text) VALUES (?, ?, ?, ?)",
		userID, req.EpisodeID, req.TimestampSec, req.Text)
	if err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}

	// Начисляем XP за комментарий (с учётом анти-фарм лимита на эпизод)
	awardCommentXP(userID, req.EpisodeID)
	newAchievements := checkAndUnlockAchievements(userID)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":                "ok",
		"unlocked_achievements": newAchievements,
	})
}

// maxVoiceCommentBytes — с запасом покрывает даже случайно длинную запись
// (короткий opus/aac-клип на десятки секунд весит десятки-сотни КБ);
// реальный лимит длительности навязывается клиентом (таймер в watch.html),
// это только защитный потолок на сервере.
const maxVoiceCommentBytes = 3 << 20 // 3 MiB

// apiVoiceCommentPost — голосовой тикер: та же лента/таблица, что текстовые
// комментарии (apiCommentPost), только вместо text заполняется audio_url.
// Одна антиспам-квота на двоих (ключ "comment:%d") — иначе спам голосом в
// обход текстового лимитера.
func apiVoiceCommentPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if !actionLimiter.allow(fmt.Sprintf("comment:%d", userID), commentRateLimit, commentRateWindow) {
		http.Error(w, `{"error":"Слишком много комментариев подряд, подождите немного"}`, http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxVoiceCommentBytes)
	episodeID, errEp := strconv.Atoi(r.FormValue("episode_id"))
	timestampSec, _ := strconv.Atoi(r.FormValue("timestamp_sec"))
	if errEp != nil || episodeID == 0 {
		http.Error(w, `{"error":"episode_id обязателен"}`, http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("audio")
	if err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, `{"error":"Запись превышает допустимый размер"}`, http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, `{"error":"Файл аудио (поле audio) обязателен"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Те же контейнеры (mp4/webm — EBML/ftyp magic bytes), что и у видео,
	// только со звуковой дорожкой — sniffVideoContainer этому уже
	// удовлетворяет, отдельная функция не нужна.
	if err := sniffVideoContainer(file); err != nil {
		http.Error(w, `{"error":"Файл не распознан как аудио/видео-контейнер (webm/mp4)"}`, http.StatusBadRequest)
		return
	}

	ext, contentType := ".webm", "audio/webm"
	if ct := header.Header.Get("Content-Type"); strings.Contains(ct, "mp4") {
		ext, contentType = ".m4a", "audio/mp4"
	}

	tmpFile, err := os.CreateTemp("", "ancen-voice-*"+ext)
	if err != nil {
		http.Error(w, `{"error":"Ошибка временного файла"}`, http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile.Name())
	if _, err := io.Copy(tmpFile, file); err != nil {
		tmpFile.Close()
		http.Error(w, `{"error":"Ошибка записи файла"}`, http.StatusInternalServerError)
		return
	}
	tmpFile.Close()

	objectName := fmt.Sprintf("voice-comments/%d-%d%s", userID, time.Now().UnixNano(), ext)
	url, err := uploadSingleFile(r.Context(), tmpFile.Name(), objectName, contentType)
	if err != nil {
		http.Error(w, `{"error":"Ошибка загрузки в хранилище"}`, http.StatusInternalServerError)
		return
	}

	if _, err := db.Exec("INSERT INTO comments (user_id, episode_id, timestamp_sec, text, audio_url) VALUES (?, ?, ?, '', ?)",
		userID, episodeID, timestampSec, url); err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}

	awardCommentXP(userID, episodeID)
	newAchievements := checkAndUnlockAchievements(userID)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":                "ok",
		"audio_url":             url,
		"unlocked_achievements": newAchievements,
	})
}

func apiCommentsGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	episodeIDStr := r.URL.Query().Get("episode_id")
	if episodeIDStr == "" {
		http.Error(w, `{"error":"episode_id required"}`, http.StatusBadRequest)
		return
	}
	episodeID, _ := strconv.Atoi(episodeIDStr)

	pageStr := r.URL.Query().Get("page")
	pageSizeStr := r.URL.Query().Get("pageSize")

	page := 1
	if pageStr != "" {
		p, err := strconv.Atoi(pageStr)
		if err == nil && p > 0 {
			page = p
		}
	}

	pageSize := 10
	if pageSizeStr != "" {
		ps, err := strconv.Atoi(pageSizeStr)
		if err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	offset := (page - 1) * pageSize

	userID, _ := getUserIDFromSession(r)
	query := `
		SELECT c.id, u.username, c.timestamp_sec, c.text, c.audio_url, c.created_at,
			(SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id) AS like_count,
			EXISTS(SELECT 1 FROM comment_likes cl WHERE cl.comment_id = c.id AND cl.user_id = ?) AS liked_by_me,
			COALESCE(ux.xp, 0)
		FROM comments c
		JOIN users u ON c.user_id = u.id
		LEFT JOIN user_xp ux ON ux.user_id = u.id
		WHERE c.episode_id = ?`
	args := []interface{}{userID, episodeID}
	if !isPremiumUser(userID) {
		query += " AND c.timestamp_sec <= ?"
		args = append(args, watchedUpToSec(userID, episodeID))
	}
	query += " ORDER BY c.timestamp_sec ASC LIMIT ? OFFSET ?"
	args = append(args, pageSize, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	comments := []Comment{}
	for rows.Next() {
		var c Comment
		var createdAt sql.NullTime
		var xp int
		if err := rows.Scan(&c.ID, &c.Username, &c.TimestampSec, &c.Text, &c.AudioURL, &createdAt, &c.LikeCount, &c.LikedByMe, &xp); err != nil {
			continue
		}
		if createdAt.Valid {
			c.CreatedAt = createdAt.Time.Format("2006-01-02 15:04:05")
		}
		level := getLevelInfo(xp).Level
		c.Badge = levelBadge(level)
		c.Color = levelColor(level)
		comments = append(comments, c)
	}
	json.NewEncoder(w).Encode(comments)
}

// apiCommentLikeToggle переключает лайк на комментарии и проверяет ачивку
// "Популярный" для автора комментария (не для того, кто лайкнул).
func apiCommentLikeToggle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var body struct {
		CommentID int `json:"comment_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.CommentID == 0 {
		http.Error(w, `{"error":"comment_id required"}`, http.StatusBadRequest)
		return
	}

	var authorID int
	if err := db.QueryRow("SELECT user_id FROM comments WHERE id = ?", body.CommentID).Scan(&authorID); err != nil {
		http.Error(w, `{"error":"comment not found"}`, http.StatusBadRequest)
		return
	}

	var exists int
	db.QueryRow("SELECT COUNT(*) FROM comment_likes WHERE user_id = ? AND comment_id = ?", userID, body.CommentID).Scan(&exists)
	if exists > 0 {
		db.Exec("DELETE FROM comment_likes WHERE user_id = ? AND comment_id = ?", userID, body.CommentID)
		var likeCount int
		db.QueryRow("SELECT COUNT(*) FROM comment_likes WHERE comment_id = ?", body.CommentID).Scan(&likeCount)
		json.NewEncoder(w).Encode(map[string]interface{}{"active": false, "like_count": likeCount})
		return
	}
	if _, err := db.Exec("INSERT INTO comment_likes (user_id, comment_id) VALUES (?, ?)", userID, body.CommentID); err != nil {
		http.Error(w, `{"error":"like failed"}`, http.StatusBadRequest)
		return
	}
	checkAndUnlockAchievements(authorID)
	var likeCount int
	db.QueryRow("SELECT COUNT(*) FROM comment_likes WHERE comment_id = ?", body.CommentID).Scan(&likeCount)
	json.NewEncoder(w).Encode(map[string]interface{}{"active": true, "like_count": likeCount})
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	genre := strings.TrimSpace(r.URL.Query().Get("genre"))

	pageStr := r.URL.Query().Get("page")
	pageSizeStr := r.URL.Query().Get("pageSize")

	page := 1
	if pageStr != "" {
		p, err := strconv.Atoi(pageStr)
		if err == nil && p > 0 {
			page = p
		}
	}

	pageSize := 24
	if pageSizeStr != "" {
		ps, err := strconv.Atoi(pageSizeStr)
		if err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	offset := (page - 1) * pageSize

	type Anime struct {
		ID          int
		Title       string
		Description string
		Poster      string
		Genres      string
	}

	// Без q/genre — это каталог "все аниме", а не пустая страница поиска
	conditions := []string{"title != ''"}
	args := []interface{}{}
	if query != "" {
		conditions = append(conditions, "(title LIKE ? OR description LIKE ? OR genres LIKE ?)")
		args = append(args, "%"+query+"%", "%"+query+"%", "%"+query+"%")
	}
	if genre != "" {
		conditions = append(conditions, "genres LIKE ?")
		args = append(args, "%"+genre+"%")
	}

	sqlQuery := "SELECT id, title, description, poster_url, genres FROM anime WHERE " +
		strings.Join(conditions, " AND ") + " ORDER BY title LIMIT ? OFFSET ?"
	rows, err := db.Query(sqlQuery, append(args, pageSize, offset)...)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []Anime
	for rows.Next() {
		var a Anime
		if err := rows.Scan(&a.ID, &a.Title, &a.Description, &a.Poster, &a.Genres); err != nil {
			continue
		}
		results = append(results, a)
	}

	// Список жанров для фильтра — реальные, разобранные из БД (не хардкод),
	// т.к. жанры хранятся свободной строкой через запятую
	genreSet := make(map[string]bool)
	genreRows, err := db.Query("SELECT DISTINCT genres FROM anime WHERE genres != ''")
	if err == nil {
		defer genreRows.Close()
		for genreRows.Next() {
			var g string
			if genreRows.Scan(&g) == nil {
				for _, part := range strings.Split(g, ",") {
					part = strings.TrimSpace(part)
					if part != "" {
						genreSet[part] = true
					}
				}
			}
		}
	}
	availableGenres := make([]string, 0, len(genreSet))
	for g := range genreSet {
		availableGenres = append(availableGenres, g)
	}
	sort.Strings(availableGenres)

	data := struct {
		Query           string
		Genre           string
		Results         []Anime
		AvailableGenres []string
		HasMore         bool
		NextPage        int
		Username        string
	}{
		Query:           query,
		Genre:           genre,
		Results:         results,
		AvailableGenres: availableGenres,
		HasMore:         len(results) == pageSize,
		NextPage:        page + 1,
		Username:        currentUsername(r),
	}
	templates.ExecuteTemplate(w, "search.html", data)
}

// robotsHandler отдаёт robots.txt — закрывает от индексации приватные/служебные
// разделы и указывает на sitemap.xml
func robotsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, `User-agent: *
Disallow: /login
Disallow: /register
Disallow: /profile
Disallow: /forgot-password
Disallow: /new-password
Disallow: /search
Disallow: /api/
Disallow: /ws

Sitemap: https://animemory.ru/sitemap.xml
`)
}

// sitemapHandler динамически формирует sitemap.xml по всем аниме и эпизодам в БД
func sitemapHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	sb.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	sb.WriteString("  <url><loc>https://animemory.ru/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>\n")

	rows, err := db.Query("SELECT id FROM anime")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			if err := rows.Scan(&id); err != nil {
				continue
			}
			fmt.Fprintf(&sb, "  <url><loc>https://animemory.ru/anime/%d</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>\n", id)
		}
	}

	epRows, err := db.Query("SELECT id FROM episodes")
	if err == nil {
		defer epRows.Close()
		for epRows.Next() {
			var id int
			if err := epRows.Scan(&id); err != nil {
				continue
			}
			fmt.Fprintf(&sb, "  <url><loc>https://animemory.ru/watch?episode=%d</loc><changefreq>monthly</changefreq><priority>0.6</priority></url>\n", id)
		}
	}

	sb.WriteString("</urlset>\n")
	fmt.Fprint(w, sb.String())
}

// maxUploadBytes — верхняя граница размера одной серии при ручной загрузке.
// ponytail: захардкожено, вынести в конфиг/env, если понадобится другой лимит.
const maxUploadBytes = 2 << 30 // 2 GiB

// sniffVideoContainer проверяет первые байты файла на сигнатуру известного
// видео-контейнера — расширение имени файла легко подделать, а вот magic bytes
// подделать так, чтобы ffmpeg всё равно смог декодировать файл, уже не тривиально.
func sniffVideoContainer(f multipart.File) error {
	head := make([]byte, 12)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return err
	}
	head = head[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	switch {
	case len(head) >= 8 && string(head[4:8]) == "ftyp": // MP4 / MOV / M4V
		return nil
	case len(head) >= 4 && bytes.Equal(head[:4], []byte{0x1A, 0x45, 0xDF, 0xA3}): // WebM / MKV (EBML)
		return nil
	case len(head) >= 12 && string(head[:4]) == "RIFF" && string(head[8:12]) == "AVI ":
		return nil
	}
	return fmt.Errorf("unrecognized video container signature")
}

// maxAvatarBytes — верхняя граница размера файла аватара.
const maxAvatarBytes = 5 << 20 // 5 MiB

// uploadImageQuality — качество JPEG для normalizeUploadedImage. 88 визуально
// неотличимо от оригинала на фото, но заметно легче любого несжатого/PNG-скана
// телефона — тот же компромисс, что использовался для статики сайта.
const uploadImageQuality = 88

// normalizeUploadedImage декодирует любой из поддерживаемых форматов (jpg/png/
// webp/gif — регистрируются через blank-импорты ниже), уменьшает картинку до
// maxDim по длинной стороне (апскейл никогда не делается — маленькое фото не
// растягиваем) и перекодирует в JPEG. Так все изображения, попадающие на сайт
// через загрузку (аватар, фон профиля, постер/баннер аниме), хранятся в одном
// предсказуемом формате и размере вместо того, что прислал браузер as-is.
// Возвращает путь к временному .jpg-файлу — вызывающий код должен его
// удалить (os.Remove) после отправки в MinIO.
func normalizeUploadedImage(file multipart.File, maxDim int) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	img, _, err := image.Decode(file)
	if err != nil {
		return "", fmt.Errorf("файл не распознан как изображение: %w", err)
	}

	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w > maxDim || h > maxDim {
		scale := float64(maxDim) / float64(w)
		if h > w {
			scale = float64(maxDim) / float64(h)
		}
		nw, nh := int(float64(w)*scale), int(float64(h)*scale)
		if nw < 1 {
			nw = 1
		}
		if nh < 1 {
			nh = 1
		}
		dst := image.NewRGBA(image.Rect(0, 0, nw, nh))
		draw.CatmullRom.Scale(dst, dst.Bounds(), img, b, draw.Over, nil)
		img = dst
	}

	tmpFile, err := os.CreateTemp("", "ancen-img-*.jpg")
	if err != nil {
		return "", err
	}
	if err := jpeg.Encode(tmpFile, img, &jpeg.Options{Quality: uploadImageQuality}); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", err
	}
	tmpFile.Close()
	return tmpFile.Name(), nil
}

// avatarFramePreset — рамка аватара, разблокируется уровнем пользователя (бесплатная
// косметика за активность, в отличие от загрузки своего файла — см. 18_Монетизация_и_уровни.md)
type avatarFramePreset struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	MinLevel int    `json:"min_level"`
	Color    string `json:"color"`
}

var avatarFramePresets = []avatarFramePreset{
	{ID: "", Name: "Без рамки", MinLevel: 1, Color: "transparent"},
	{ID: "bronze", Name: "Бронзовая", MinLevel: 3, Color: "#9A5B32"},
	{ID: "silver", Name: "Серебряная", MinLevel: 6, Color: "#C0C0C0"},
	{ID: "gold", Name: "Золотая", MinLevel: 9, Color: "#FFCC00"},
}

func avatarFrameByID(id string) (avatarFramePreset, bool) {
	for _, f := range avatarFramePresets {
		if f.ID == id {
			return f, true
		}
	}
	return avatarFramePreset{}, false
}

// chartColorPreset — цвет графика реакций на watch.html, разблокируется уровнем
// (та же схема, что avatarFramePreset: выбор пользователем из бесплатных пресетов).
type chartColorPreset struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	MinLevel   int    `json:"min_level"`
	Color      string `json:"color"`
	HoverColor string `json:"hover_color"`
}

var chartColorPresets = []chartColorPreset{
	{ID: "", Name: "По умолчанию", MinLevel: 1, Color: "#d82d7e", HoverColor: "#ff5fa8"},
	{ID: "teal", Name: "Бирюзовый", MinLevel: 3, Color: "#2dd8a8", HoverColor: "#5fffce"},
	{ID: "gold", Name: "Золотой", MinLevel: 6, Color: "#d8b62d", HoverColor: "#ffe45f"},
	{ID: "violet", Name: "Фиолетовый", MinLevel: 9, Color: "#8a2dd8", HoverColor: "#b85fff"},
	{ID: "ice", Name: "Ледяной", MinLevel: 12, Color: "#2d9ed8", HoverColor: "#5fd4ff"},
}

func chartColorByID(id string) (chartColorPreset, bool) {
	for _, c := range chartColorPresets {
		if c.ID == id {
			return c, true
		}
	}
	return chartColorPreset{}, false
}

// apiAvatarUploadHandler принимает файл аватара — бесплатно для всех пользователей
// (решение 2026-08-14, см. 18_Монетизация_и_уровни.md: перенесено из Premium в
// бесплатную версию наравне с 1080p/ранним доступом).
func apiAvatarUploadHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAvatarBytes)
	file, _, err := r.FormFile("avatar")
	if err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, `{"error":"Файл превышает 5 МБ"}`, http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, `{"error":"Файл (поле avatar) обязателен"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	tmpPath, err := normalizeUploadedImage(file, 512)
	if err != nil {
		http.Error(w, `{"error":"Файл не распознан как изображение (jpg/png/webp)"}`, http.StatusBadRequest)
		return
	}
	defer os.Remove(tmpPath)

	objectName := fmt.Sprintf("avatars/%d-%d.jpg", userID, time.Now().UnixNano())
	url, err := uploadSingleFile(r.Context(), tmpPath, objectName, "image/jpeg")
	if err != nil {
		http.Error(w, `{"error":"Ошибка загрузки в хранилище"}`, http.StatusInternalServerError)
		return
	}

	if _, err := db.Exec("UPDATE users SET avatar_url = ? WHERE id = ?", url, userID); err != nil {
		http.Error(w, `{"error":"Ошибка сохранения аватара"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "avatar_url": url})
}

// apiBackgroundUploadHandler — загрузка своего фона профиля, тот же паттерн,
// что apiAvatarUploadHandler (Premium-гейт, magic-bytes, MinIO).
// backgroundUploadMinLevel — свой фон профиля доступен бесплатно с этого уровня
// (решение 2026-08-14: перенесено из Premium в бесплатную версию, та же логика,
// что рамки аватара/цвет графика — косметика за активность, не за деньги).
const backgroundUploadMinLevel = 2

func apiBackgroundUploadHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if userLevel(userID) < backgroundUploadMinLevel {
		http.Error(w, fmt.Sprintf(`{"error":"Свой фон разблокируется на уровне %d"}`, backgroundUploadMinLevel), http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAvatarBytes)
	file, _, err := r.FormFile("background")
	if err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, `{"error":"Файл превышает 5 МБ"}`, http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, `{"error":"Файл (поле background) обязателен"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	tmpPath, err := normalizeUploadedImage(file, 1920)
	if err != nil {
		http.Error(w, `{"error":"Файл не распознан как изображение (jpg/png/webp)"}`, http.StatusBadRequest)
		return
	}
	defer os.Remove(tmpPath)

	objectName := fmt.Sprintf("backgrounds/%d-%d.jpg", userID, time.Now().UnixNano())
	url, err := uploadSingleFile(r.Context(), tmpPath, objectName, "image/jpeg")
	if err != nil {
		http.Error(w, `{"error":"Ошибка загрузки в хранилище"}`, http.StatusInternalServerError)
		return
	}

	if _, err := db.Exec("UPDATE users SET background_url = ? WHERE id = ?", url, userID); err != nil {
		http.Error(w, `{"error":"Ошибка сохранения фона"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "background_url": url})
}

// apiWatchingActivityToggleHandler переключает видимость в ленте активности
// друзей ("Х сейчас смотрит Y") — решено 2026-08-14, приватность сразу вместе
// с фичей, а не отдельным заходом.
func apiWatchingActivityToggleHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var current bool
	db.QueryRow("SELECT show_watching_activity FROM users WHERE id = ?", userID).Scan(&current)
	newValue := !current
	if _, err := db.Exec("UPDATE users SET show_watching_activity = ? WHERE id = ?", newValue, userID); err != nil {
		http.Error(w, `{"error":"Ошибка сохранения"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]bool{"value": newValue})
}

// apiBackgroundRemoveHandler сбрасывает фон профиля обратно на дефолтный.
func apiBackgroundRemoveHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if _, err := db.Exec("UPDATE users SET background_url = ? WHERE id = ?", defaultBackgroundURL, userID); err != nil {
		http.Error(w, `{"error":"Ошибка сохранения"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "background_url": defaultBackgroundURL})
}

// apiAvatarFrameHandler устанавливает рамку аватара из бесплатных пресетов,
// разблокированных уровнем пользователя.
func apiAvatarFrameHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		FrameID string `json:"frame_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
		return
	}
	frame, ok := avatarFrameByID(req.FrameID)
	if !ok {
		http.Error(w, `{"error":"Неизвестная рамка"}`, http.StatusBadRequest)
		return
	}
	var xp int
	db.QueryRow("SELECT xp FROM user_xp WHERE user_id = ?", userID).Scan(&xp)
	if getLevelInfo(xp).Level < frame.MinLevel {
		http.Error(w, `{"error":"Рамка ещё не разблокирована — нужен более высокий уровень"}`, http.StatusForbidden)
		return
	}
	if _, err := db.Exec("UPDATE users SET avatar_frame = ? WHERE id = ?", frame.ID, userID); err != nil {
		http.Error(w, `{"error":"Ошибка сохранения"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// apiChartColorHandler устанавливает цвет графика реакций из бесплатных пресетов,
// разблокированных уровнем пользователя (тот же паттерн, что apiAvatarFrameHandler).
func apiChartColorHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		ColorID string `json:"color_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
		return
	}
	preset, ok := chartColorByID(req.ColorID)
	if !ok {
		http.Error(w, `{"error":"Неизвестный цвет"}`, http.StatusBadRequest)
		return
	}
	var xp int
	db.QueryRow("SELECT xp FROM user_xp WHERE user_id = ?", userID).Scan(&xp)
	if getLevelInfo(xp).Level < preset.MinLevel {
		http.Error(w, `{"error":"Цвет ещё не разблокирован — нужен более высокий уровень"}`, http.StatusForbidden)
		return
	}
	if _, err := db.Exec("UPDATE users SET chart_color = ? WHERE id = ?", preset.ID, userID); err != nil {
		http.Error(w, `{"error":"Ошибка сохранения"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// adminBarItem — одна строка в полосе-метрике (лейбл + значение + % от максимума
// в группе, посчитанный на Go-стороне, чтобы шаблон просто вставлял готовую ширину).
type adminBarItem struct {
	Label   string
	Value   int
	Percent int
}

// buildBarItems считает Percent относительно максимального Value в срезе —
// общий хелпер для всех полос-метрик дашборда (реакции по типам, топ аниме, топ XP).
func buildBarItems(labels []string, values []int) []adminBarItem {
	max := 0
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	items := make([]adminBarItem, len(labels))
	for i, l := range labels {
		percent := 0
		if max > 0 {
			percent = values[i] * 100 / max
		}
		items[i] = adminBarItem{Label: l, Value: values[i], Percent: percent}
	}
	return items
}

// adminStatRow — одна строка таблицы "статистика пользователей" на /admin
// (цель / результат / % выполнения).
type adminStatRow struct {
	Label   string
	Goal    string
	Result  string
	Percent int
}

// formatThousands форматирует число с пробелом-разделителем разрядов
// ("25467" → "25 467"), как в дизайне Figma.
func formatThousands(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ' ')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

// goalPercent — % выполнения результата от цели, ограниченный [0,100].
func goalPercent(result, goal float64) int {
	if goal <= 0 {
		return 0
	}
	p := int(result / goal * 100)
	if p > 100 {
		p = 100
	}
	if p < 0 {
		p = 0
	}
	return p
}

// countSince — COUNT(*) из table.column за последние since (INTERVAL в SQL
// собирается через плейсхолдер нельзя, поэтому since передаётся строкой дней).
func countSince(query string, args ...interface{}) int {
	var c int
	db.QueryRow(query, args...).Scan(&c)
	return c
}

// adminDashboardHandler — GET /admin. Требует is_admin=1 (см. adminUploadVideoHandler).
func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !isUserAdmin(userID) {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	totalUsers := countSince("SELECT COUNT(*) FROM users")

	// MAU — доля пользователей с визитом за последние 30 дней от общего числа.
	activeUsers30d := countSince(`SELECT COUNT(DISTINCT user_id) FROM admin_visits
		WHERE user_id IS NOT NULL AND created_at >= NOW() - INTERVAL 30 DAY`)
	mauPercent := 0.0
	if totalUsers > 0 {
		mauPercent = float64(activeUsers30d) / float64(totalUsers) * 100
	}

	// Средняя длительность сессии (мин) — по группам (session_id, день) с
	// более чем одним визитом за последние 30 дней.
	var avgSessionSec sql.NullFloat64
	db.QueryRow(`SELECT AVG(dur) FROM (
		SELECT TIMESTAMPDIFF(SECOND, MIN(created_at), MAX(created_at)) dur
		FROM admin_visits WHERE created_at >= NOW() - INTERVAL 30 DAY
		GROUP BY session_id, DATE(created_at) HAVING COUNT(*) > 1
	) t`).Scan(&avgSessionSec)
	avgSessionMin := avgSessionSec.Float64 / 60

	// Средние посещения в неделю на пользователя — за последние 28 дней (4 недели).
	visits28d := countSince(`SELECT COUNT(*) FROM admin_visits
		WHERE user_id IS NOT NULL AND created_at >= NOW() - INTERVAL 28 DAY`)
	users28d := countSince(`SELECT COUNT(DISTINCT user_id) FROM admin_visits
		WHERE user_id IS NOT NULL AND created_at >= NOW() - INTERVAL 28 DAY`)
	avgVisitsPerWeek := 0.0
	if users28d > 0 {
		avgVisitsPerWeek = float64(visits28d) / float64(users28d) / 4
	}

	reactionsPerDay := countSince("SELECT COUNT(*) FROM emotions WHERE created_at >= NOW() - INTERVAL 1 DAY")
	commentsPerDay := countSince("SELECT COUNT(*) FROM comments WHERE created_at >= NOW() - INTERVAL 1 DAY")
	friendReqPerWeek := countSince("SELECT COUNT(*) FROM friendships WHERE created_at >= NOW() - INTERVAL 7 DAY")

	stats := []adminStatRow{
		{"кол-во авторизаций", "2 000", formatThousands(totalUsers), goalPercent(float64(totalUsers), 2000)},
		{"MAU", "60–70%", fmt.Sprintf("%.0f%%", mauPercent), goalPercent(mauPercent, 65)},
		{"средняя сессия", "15 мин", fmt.Sprintf("%.0f мин", avgSessionMin), goalPercent(avgSessionMin, 15)},
		{"Ср. посещений в неделю", "2-3", fmt.Sprintf("%.1f", avgVisitsPerWeek), goalPercent(avgVisitsPerWeek, 2.5)},
		{"Реакций/день", "1 500", formatThousands(reactionsPerDay), goalPercent(float64(reactionsPerDay), 1500)},
		{"Комментариев/день", "150", strconv.Itoa(commentsPerDay), goalPercent(float64(commentsPerDay), 150)},
		{"Заявок в друзья/неделю", "200", strconv.Itoa(friendReqPerWeek), goalPercent(float64(friendReqPerWeek), 200)},
	}
	overallPercent := 0
	for _, s := range stats {
		overallPercent += s.Percent
	}
	overallPercent /= len(stats)

	// Визиты и средняя сессия по дням за последние 14 дней — для линейных графиков.
	visitsByDay := make(map[string]int)
	if rows, err := db.Query(`SELECT DATE(created_at) d, COUNT(*) c FROM admin_visits
		WHERE created_at >= NOW() - INTERVAL 14 DAY GROUP BY d`); err == nil {
		for rows.Next() {
			var d string
			var c int
			if rows.Scan(&d, &c) == nil {
				visitsByDay[d] = c
			}
		}
		rows.Close()
	}
	sessionByDay := make(map[string]float64)
	if rows, err := db.Query(`SELECT d, AVG(dur)/60 FROM (
		SELECT session_id, DATE(created_at) d, TIMESTAMPDIFF(SECOND, MIN(created_at), MAX(created_at)) dur
		FROM admin_visits WHERE created_at >= NOW() - INTERVAL 14 DAY
		GROUP BY session_id, d HAVING COUNT(*) > 1
	) t GROUP BY d`); err == nil {
		for rows.Next() {
			var d string
			var m float64
			if rows.Scan(&d, &m) == nil {
				sessionByDay[d] = m
			}
		}
		rows.Close()
	}
	visits14 := make([]int, 14)
	sessions14 := make([]float64, 14)
	for i := 0; i < 14; i++ {
		day := time.Now().AddDate(0, 0, -13+i).Format("2006-01-02")
		visits14[i] = visitsByDay[day]
		sessions14[i] = math.Round(sessionByDay[day]*10) / 10
	}

	// Разбивка визитов по устройствам за текущий месяц — для доната.
	var mobileCount, desktopCount int
	db.QueryRow(`SELECT COUNT(*) FROM admin_visits WHERE device = 'mobile'
		AND created_at >= DATE_FORMAT(NOW(), '%Y-%m-01')`).Scan(&mobileCount)
	db.QueryRow(`SELECT COUNT(*) FROM admin_visits WHERE device = 'desktop'
		AND created_at >= DATE_FORMAT(NOW(), '%Y-%m-01')`).Scan(&desktopCount)

	monthNames := []string{"", "Январь", "Февраль", "Март", "Апрель", "Май", "Июнь",
		"Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"}
	now := time.Now()
	monthLabel := fmt.Sprintf("%s %d", monthNames[now.Month()], now.Year())

	// JSON-снимок для JS-рендера карточек (admin_dashboard.html) — единая
	// точка, куда в будущем добавляются новые метрики без правки шаблона.
	dashboardJSON, err := json.Marshal(map[string]interface{}{
		"stats":          stats,
		"overallPercent": overallPercent,
		"visits14":       visits14,
		"sessions14":     sessions14,
		"devices":        map[string]int{"mobile": mobileCount, "desktop": desktopCount},
		"monthLabel":     monthLabel,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := currentUsername(r)
	initial := "?"
	if runes := []rune(username); len(runes) > 0 {
		initial = strings.ToUpper(string(runes[:1]))
	}

	data := struct {
		Username          string
		AdminInitial      string
		AdminAvatarURL    string
		Stats             []adminStatRow
		OverallPercent    int
		DashboardDataJSON template.JS
	}{
		Username:          username,
		AdminInitial:      initial,
		AdminAvatarURL:    currentAvatarURL(userID),
		Stats:             stats,
		OverallPercent:    overallPercent,
		DashboardDataJSON: template.JS(dashboardJSON),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "admin_dashboard.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// adminUserRow — одна строка таблицы на /admin/users.
type adminUserRow struct {
	ID        int
	Username  string
	XP        int
	Level     int
	IsPremium bool
	IsAdmin   bool
	IsBanned  bool
	CreatedAt string
}

const adminUsersPageSize = 15

// ponytail: не ограничено, при росте базы админов/премиумов на порядки
// стоит добавить пагинацию и в нижние плашки.
const adminUsersPanelLimit = 300

// levelXPRange возвращает диапазон XP, соответствующий уровню level (для
// фильтра по уровню в /admin/users — уровень не хранится в БД, только XP).
func levelXPRange(level int) (minXP int, maxXP int, hasMax bool) {
	if level < 1 {
		level = 1
	}
	if level-1 < len(levelXPRequirements) {
		minXP = levelXPRequirements[level-1]
	}
	if level < len(levelXPRequirements) {
		maxXP = levelXPRequirements[level]
		hasMax = true
	}
	return
}

// adminUsersFilterConds разбирает общие query-параметры фильтра (q/level/date_from/date_to)
// из запроса в список условий+args — переиспользуется и в основной таблице, и в
// плашках премиум/админов (с добавлением своего is_premium=1/is_admin=1), и в
// apiAdminUsersList (подгрузка "Показать ещё"), чтобы фильтры не терялись при пагинации.
func adminUsersFilterConds(r *http.Request) (conds []string, args []interface{}) {
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		conds = append(conds, "u.username LIKE ?")
		args = append(args, "%"+q+"%")
	}
	if levelStr := r.URL.Query().Get("level"); levelStr != "" {
		if level, err := strconv.Atoi(levelStr); err == nil && level >= 1 {
			minXP, maxXP, hasMax := levelXPRange(level)
			conds = append(conds, "COALESCE(ux.xp, 0) >= ?")
			args = append(args, minXP)
			if hasMax {
				conds = append(conds, "COALESCE(ux.xp, 0) < ?")
				args = append(args, maxXP)
			}
		}
	}
	if dateFrom := r.URL.Query().Get("date_from"); dateFrom != "" {
		if _, err := time.Parse("2006-01-02", dateFrom); err == nil {
			conds = append(conds, "u.created_at >= ?")
			args = append(args, dateFrom)
		}
	}
	if dateTo := r.URL.Query().Get("date_to"); dateTo != "" {
		if t, err := time.Parse("2006-01-02", dateTo); err == nil {
			conds = append(conds, "u.created_at < ?")
			args = append(args, t.AddDate(0, 0, 1).Format("2006-01-02"))
		}
	}
	return
}

// buildWhere собирает WHERE-условие из базового условия (например "u.is_premium = 1",
// может быть пустым) и общих фильтров из adminUsersFilterConds.
func buildWhere(baseCond string, baseArgs []interface{}, conds []string, condArgs []interface{}) (string, []interface{}) {
	all := []string{}
	args := []interface{}{}
	if baseCond != "" {
		all = append(all, baseCond)
		args = append(args, baseArgs...)
	}
	all = append(all, conds...)
	args = append(args, condArgs...)
	if len(all) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(all, " AND "), args
}

// queryAdminUsers — общий запрос списка пользователей с опциональным WHERE,
// используется и для основной таблицы (постранично), и для плашек
// премиум/админов (весь список), и для JSON-подгрузки "показать ещё".
func queryAdminUsers(where string, args []interface{}, limit, offset int) ([]adminUserRow, error) {
	rowsArgs := append(append([]interface{}{}, args...), limit, offset)
	rows, err := db.Query(`
		SELECT u.id, u.username, COALESCE(ux.xp, 0), u.is_premium, u.is_admin, u.is_banned, u.created_at
		FROM users u
		LEFT JOIN user_xp ux ON ux.user_id = u.id
		`+where+`
		ORDER BY u.id DESC
		LIMIT ? OFFSET ?
	`, rowsArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []adminUserRow
	for rows.Next() {
		var u adminUserRow
		var createdAt sql.NullTime
		if err := rows.Scan(&u.ID, &u.Username, &u.XP, &u.IsPremium, &u.IsAdmin, &u.IsBanned, &createdAt); err != nil {
			continue
		}
		u.Level = getLevelInfo(u.XP).Level
		if createdAt.Valid {
			u.CreatedAt = createdAt.Time.Format("02.01.2006")
		}
		users = append(users, u)
	}
	return users, nil
}

// adminUsersHandler — GET /admin/users. Верхняя плашка — общий список
// пользователей (первые 15, дальше подгружаются через apiAdminUsersList),
// нижние плашки — полные списки премиум/админов, управление ролями идёт
// через apiAdminUserToggle.
func adminUsersHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !isUserAdmin(userID) {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	level := strings.TrimSpace(r.URL.Query().Get("level"))
	dateFrom := strings.TrimSpace(r.URL.Query().Get("date_from"))
	dateTo := strings.TrimSpace(r.URL.Query().Get("date_to"))
	conds, condArgs := adminUsersFilterConds(r)
	where, args := buildWhere("", nil, conds, condArgs)

	var total int
	db.QueryRow("SELECT COUNT(*) FROM users u LEFT JOIN user_xp ux ON ux.user_id = u.id "+where, args...).Scan(&total)

	users, err := queryAdminUsers(where, args, adminUsersPageSize, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	premiumWhere, premiumArgs := buildWhere("u.is_premium = 1", nil, conds, condArgs)
	adminWhere, adminArgs := buildWhere("u.is_admin = 1", nil, conds, condArgs)
	premiumUsers, err := queryAdminUsers(premiumWhere, premiumArgs, adminUsersPanelLimit, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	adminUsers, err := queryAdminUsers(adminWhere, adminArgs, adminUsersPanelLimit, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := currentUsername(r)
	initial := "?"
	if runes := []rune(username); len(runes) > 0 {
		initial = strings.ToUpper(string(runes[:1]))
	}

	data := struct {
		Username       string
		AdminInitial   string
		AdminAvatarURL string
		Users          []adminUserRow
		PremiumUsers   []adminUserRow
		AdminUsers     []adminUserRow
		Query          string
		Level          string
		Levels         []int
		DateFrom       string
		DateTo         string
		Total          int
		HasMore        bool
		NextOffset     int
	}{
		Username:       username,
		AdminInitial:   initial,
		AdminAvatarURL: currentAvatarURL(userID),
		Users:          users,
		PremiumUsers: premiumUsers,
		AdminUsers:   adminUsers,
		Query:        q,
		Level:        level,
		Levels:       []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		DateFrom:     dateFrom,
		DateTo:       dateTo,
		Total:        total,
		HasMore:      len(users) < total,
		NextOffset:   len(users),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "admin_users.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// apiAdminUsersList — GET /api/admin/users?q=&offset= — JSON-подгрузка
// следующих adminUsersPageSize пользователей для кнопки "Показать ещё".
func apiAdminUsersList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil || !isUserAdmin(userID) {
		http.Error(w, `{"error":"Доступ запрещён"}`, http.StatusForbidden)
		return
	}

	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}

	conds, condArgs := adminUsersFilterConds(r)
	where, args := buildWhere("", nil, conds, condArgs)

	var total int
	db.QueryRow("SELECT COUNT(*) FROM users u LEFT JOIN user_xp ux ON ux.user_id = u.id "+where, args...).Scan(&total)

	users, err := queryAdminUsers(where, args, adminUsersPageSize, offset)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(struct {
		Users      []adminUserRow `json:"users"`
		HasMore    bool           `json:"has_more"`
		NextOffset int            `json:"next_offset"`
	}{
		Users:      users,
		HasMore:    offset+len(users) < total,
		NextOffset: offset + len(users),
	})
}

type analyticsRow struct {
	Title     string
	Sub       string
	AnimeID   int
	Views     int
	Reactions int
	Comments  int
}

// adminAnalyticsHandler — GET /admin/analytics. Топ-20 аниме и топ-20
// эпизодов по вовлечённости (просмотры из user_progress, реакции из
// emotions, комментарии из comments).
func adminAnalyticsHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !isUserAdmin(userID) {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	episodeRows, err := db.Query(`
		SELECT a.title, CONCAT('Эп. ', e.episode_num, ' — ', e.title), a.id,
			COALESCE(v.views,0), COALESCE(rc.reactions,0), COALESCE(c.comments,0)
		FROM episodes e
		JOIN anime a ON a.id = e.anime_id
		LEFT JOIN (SELECT episode_id, COUNT(*) views FROM user_progress GROUP BY episode_id) v ON v.episode_id = e.id
		LEFT JOIN (SELECT episode_id, COUNT(*) reactions FROM emotions GROUP BY episode_id) rc ON rc.episode_id = e.id
		LEFT JOIN (SELECT episode_id, COUNT(*) comments FROM comments GROUP BY episode_id) c ON c.episode_id = e.id
		ORDER BY (COALESCE(v.views,0)+COALESCE(rc.reactions,0)+COALESCE(c.comments,0)) DESC
		LIMIT 20
	`)
	var episodes []analyticsRow
	if err == nil {
		defer episodeRows.Close()
		for episodeRows.Next() {
			var row analyticsRow
			if episodeRows.Scan(&row.Title, &row.Sub, &row.AnimeID, &row.Views, &row.Reactions, &row.Comments) == nil {
				episodes = append(episodes, row)
			}
		}
	}

	animeRows, err := db.Query(`
		SELECT a.title, a.id,
			COALESCE(SUM(v.views),0), COALESCE(SUM(rc.reactions),0), COALESCE(SUM(c.comments),0)
		FROM anime a
		JOIN episodes e ON e.anime_id = a.id
		LEFT JOIN (SELECT episode_id, COUNT(*) views FROM user_progress GROUP BY episode_id) v ON v.episode_id = e.id
		LEFT JOIN (SELECT episode_id, COUNT(*) reactions FROM emotions GROUP BY episode_id) rc ON rc.episode_id = e.id
		LEFT JOIN (SELECT episode_id, COUNT(*) comments FROM comments GROUP BY episode_id) c ON c.episode_id = e.id
		GROUP BY a.id, a.title
		ORDER BY (SUM(COALESCE(v.views,0))+SUM(COALESCE(rc.reactions,0))+SUM(COALESCE(c.comments,0))) DESC
		LIMIT 20
	`)
	var anime []analyticsRow
	if err == nil {
		defer animeRows.Close()
		for animeRows.Next() {
			var row analyticsRow
			if animeRows.Scan(&row.Title, &row.AnimeID, &row.Views, &row.Reactions, &row.Comments) == nil {
				anime = append(anime, row)
			}
		}
	}

	username := currentUsername(r)
	initial := "?"
	if runes := []rune(username); len(runes) > 0 {
		initial = strings.ToUpper(string(runes[:1]))
	}

	data := struct {
		Username       string
		AdminInitial   string
		AdminAvatarURL string
		Anime          []analyticsRow
		Episodes       []analyticsRow
	}{
		Username:       username,
		AdminInitial:   initial,
		AdminAvatarURL: currentAvatarURL(userID),
		Anime:          anime,
		Episodes:       episodes,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "admin_analytics.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// adminSettingsHandler — GET /admin/settings. Единственная настройка на
// сегодня — maintenance mode, переключается через apiAdminMaintenanceToggle.
func adminSettingsHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !isUserAdmin(userID) {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	username := currentUsername(r)
	initial := "?"
	if runes := []rune(username); len(runes) > 0 {
		initial = strings.ToUpper(string(runes[:1]))
	}

	data := struct {
		Username        string
		AdminInitial    string
		AdminAvatarURL  string
		MaintenanceMode bool
	}{
		Username:        username,
		AdminInitial:    initial,
		AdminAvatarURL:  currentAvatarURL(userID),
		MaintenanceMode: maintenanceMode.Load(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "admin_settings.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// apiAdminMaintenanceToggle переключает maintenance mode для всего сайта
// (см. maintenanceGate) и сохраняет значение в app_settings.
func apiAdminMaintenanceToggle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	adminID, err := getUserIDFromSession(r)
	if err != nil || !isUserAdmin(adminID) {
		http.Error(w, `{"error":"Доступ запрещён"}`, http.StatusForbidden)
		return
	}

	newValue := !maintenanceMode.Load()
	if _, err := db.Exec("UPDATE app_settings SET maintenance_mode = ? WHERE id = 1", newValue); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	maintenanceMode.Store(newValue)

	json.NewEncoder(w).Encode(struct {
		Value bool `json:"value"`
	}{Value: newValue})
}

// apiAdminUserToggle переключает одну из ролевых меток пользователя
// (is_premium/is_admin/is_banned) из /admin/users. Список полей захардкожен —
// принимать произвольное имя колонки от клиента небезопасно (SQL injection
// через идентификатор, не через значение).
func apiAdminUserToggle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	adminID, err := getUserIDFromSession(r)
	if err != nil || !isUserAdmin(adminID) {
		http.Error(w, `{"error":"Доступ запрещён"}`, http.StatusForbidden)
		return
	}
	var body struct {
		UserID int    `json:"user_id"`
		Field  string `json:"field"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.UserID == 0 {
		http.Error(w, `{"error":"user_id required"}`, http.StatusBadRequest)
		return
	}

	column, ok := map[string]string{
		"is_premium": "is_premium",
		"is_admin":   "is_admin",
		"is_banned":  "is_banned",
	}[body.Field]
	if !ok {
		http.Error(w, `{"error":"unknown field"}`, http.StatusBadRequest)
		return
	}
	if column == "is_admin" && body.UserID == adminID {
		http.Error(w, `{"error":"нельзя снять права администратора с самого себя"}`, http.StatusBadRequest)
		return
	}

	var current bool
	if err := db.QueryRow("SELECT "+column+" FROM users WHERE id = ?", body.UserID).Scan(&current); err != nil {
		http.Error(w, `{"error":"пользователь не найден"}`, http.StatusNotFound)
		return
	}
	newValue := !current
	if _, err := db.Exec("UPDATE users SET "+column+" = ? WHERE id = ?", newValue, body.UserID); err != nil {
		http.Error(w, `{"error":"ошибка сохранения"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]bool{"value": newValue})
}

// adminAnimeRow — строка списка на /admin/catalog.
type adminAnimeRow struct {
	ID            int
	Title         string
	Year          string
	Poster        string
	EpisodesCount int
}

const adminCatalogPageSize = 20

// requireAdminPage — общая проверка сессии+роли для GET-страниц админки.
// Возвращает 0 и уже отправленный редирект/ошибку, если доступа нет.
func requireAdminPage(w http.ResponseWriter, r *http.Request) int {
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return 0
	}
	if !isUserAdmin(userID) {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return 0
	}
	return userID
}

// adminInitial — первая буква имени залогиненного администратора, для
// аватара-заглушки в шапке /admin/*.
func adminInitial(r *http.Request, userID int) (string, string, string) {
	username := currentUsername(r)
	initial := "?"
	if runes := []rune(username); len(runes) > 0 {
		initial = strings.ToUpper(string(runes[:1]))
	}
	return username, initial, currentAvatarURL(userID)
}

// adminCatalogHandler — GET /admin/catalog. Список аниме с поиском по
// названию, числом эпизодов и постером; добавление/редактирование/удаление —
// через apiAdminAnimeUpsert/apiAdminAnimeDelete.
func adminCatalogHandler(w http.ResponseWriter, r *http.Request) {
	adminUserID := requireAdminPage(w, r)
	if adminUserID == 0 {
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * adminCatalogPageSize

	where := ""
	args := []interface{}{}
	if q != "" {
		where = "WHERE a.title LIKE ?"
		args = append(args, "%"+q+"%")
	}

	var total int
	db.QueryRow("SELECT COUNT(*) FROM anime a "+where, args...).Scan(&total)

	rowsArgs := append(append([]interface{}{}, args...), adminCatalogPageSize, offset)
	rows, err := db.Query(`
		SELECT a.id, a.title, a.year, a.poster_url, COUNT(e.id)
		FROM anime a
		LEFT JOIN episodes e ON e.anime_id = a.id
		`+where+`
		GROUP BY a.id
		ORDER BY a.id DESC
		LIMIT ? OFFSET ?
	`, rowsArgs...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var list []adminAnimeRow
	for rows.Next() {
		var a adminAnimeRow
		if rows.Scan(&a.ID, &a.Title, &a.Year, &a.Poster, &a.EpisodesCount) == nil {
			list = append(list, a)
		}
	}

	totalPages := (total + adminCatalogPageSize - 1) / adminCatalogPageSize
	if totalPages < 1 {
		totalPages = 1
	}

	username, initial, avatarURL := adminInitial(r, adminUserID)
	data := struct {
		Username       string
		AdminInitial   string
		AdminAvatarURL string
		Anime          []adminAnimeRow
		Query          string
		Page           int
		TotalPages     int
		Total          int
	}{
		Username: username, AdminInitial: initial, AdminAvatarURL: avatarURL,
		Anime: list, Query: q, Page: page, TotalPages: totalPages, Total: total,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "admin_catalog.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// adminEpisodeRow — строка таблицы эпизодов на /admin/catalog/anime.
type adminEpisodeRow struct {
	ID         int
	EpisodeNum int
	Season     int
	Title      string
	Poster     string
	HasVideo   bool
}

// adminAnimeDetailHandler — GET /admin/catalog/anime?id=. Метаданные аниме
// (форма редактирования) + список его эпизодов с удалением/добавлением.
func adminAnimeDetailHandler(w http.ResponseWriter, r *http.Request) {
	adminUserID := requireAdminPage(w, r)
	if adminUserID == 0 {
		return
	}

	animeID, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	type animeDetail struct {
		ID          int
		Title       string
		Description string
		Poster      string
		Banner      string
		Genres      string
		Year        string
		Country     string
		SourceType  string
		Studio      string
		Author      string
		Director    string
	}
	var a animeDetail
	err = db.QueryRow(`
		SELECT id, title, description, poster_url, banner_url, genres, year, country, source_type, studio, author, director
		FROM anime WHERE id = ?
	`, animeID).Scan(&a.ID, &a.Title, &a.Description, &a.Poster, &a.Banner, &a.Genres, &a.Year, &a.Country, &a.SourceType, &a.Studio, &a.Author, &a.Director)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var episodes []adminEpisodeRow
	rows, err := db.Query(`
		SELECT id, episode_num, season, title, video_url, poster_url
		FROM episodes WHERE anime_id = ? ORDER BY season, episode_num
	`, animeID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e adminEpisodeRow
			var videoURL string
			if rows.Scan(&e.ID, &e.EpisodeNum, &e.Season, &e.Title, &videoURL, &e.Poster) == nil {
				e.HasVideo = videoURL != ""
				episodes = append(episodes, e)
			}
		}
	}

	username, initial, avatarURL := adminInitial(r, adminUserID)
	data := struct {
		Username        string
		AdminInitial    string
		AdminAvatarURL  string
		Anime           animeDetail
		Episodes        []adminEpisodeRow
		AvailableGenres []string
	}{Username: username, AdminInitial: initial, AdminAvatarURL: avatarURL, Anime: a, Episodes: episodes, AvailableGenres: animeGenreList}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "admin_catalog_anime.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// animeUpsertBody — общее тело для создания и редактирования аниме.
type animeUpsertBody struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Poster      string `json:"poster_url"`
	Banner      string `json:"banner_url"`
	Genres      string `json:"genres"`
	Year        string `json:"year"`
	Country     string `json:"country"`
	SourceType  string `json:"source_type"`
	Studio      string `json:"studio"`
	Author      string `json:"author"`
	Director    string `json:"director"`
}

// apiAdminAnimeUpsert — POST /api/admin/anime/save. body.ID == 0 создаёт
// новую запись, иначе обновляет существующую.
func apiAdminAnimeUpsert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	adminID, err := getUserIDFromSession(r)
	if err != nil || !isUserAdmin(adminID) {
		http.Error(w, `{"error":"Доступ запрещён"}`, http.StatusForbidden)
		return
	}
	var b animeUpsertBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || strings.TrimSpace(b.Title) == "" {
		http.Error(w, `{"error":"title обязателен"}`, http.StatusBadRequest)
		return
	}

	if b.ID == 0 {
		res, err := db.Exec(`
			INSERT INTO anime (title, description, poster_url, banner_url, genres, year, country, source_type, studio, author, director)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, b.Title, b.Description, b.Poster, b.Banner, b.Genres, b.Year, b.Country, b.SourceType, b.Studio, b.Author, b.Director)
		if err != nil {
			http.Error(w, `{"error":"ошибка сохранения"}`, http.StatusInternalServerError)
			return
		}
		id, _ := res.LastInsertId()
		json.NewEncoder(w).Encode(map[string]int{"id": int(id)})
		return
	}

	_, err = db.Exec(`
		UPDATE anime SET title=?, description=?, poster_url=?, banner_url=?, genres=?, year=?, country=?, source_type=?, studio=?, author=?, director=?
		WHERE id = ?
	`, b.Title, b.Description, b.Poster, b.Banner, b.Genres, b.Year, b.Country, b.SourceType, b.Studio, b.Author, b.Director, b.ID)
	if err != nil {
		http.Error(w, `{"error":"ошибка сохранения"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]int{"id": b.ID})
}

// animeImageMaxDim — целевой максимальный размер по длинной стороне для
// постера (узкий, карточки/страница аниме) и баннера (широкий, "Новое" на
// главной) — баннер шире, поэтому лимит выше.
var animeImageMaxDim = map[string]int{"poster": 900, "banner": 1920}

// apiAdminAnimeImageUpload — POST /api/admin/anime/image, multipart с полями
// kind ("poster"|"banner") и image. Загрузка отдельно от apiAdminAnimeUpsert
// (тот принимает JSON) — та же схема, что apiAvatarUploadHandler: сначала
// заливаем файл и получаем URL, потом сохраняем его строкой через save.
func apiAdminAnimeImageUpload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	adminID, err := getUserIDFromSession(r)
	if err != nil || !isUserAdmin(adminID) {
		http.Error(w, `{"error":"Доступ запрещён"}`, http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAvatarBytes)
	kind := r.FormValue("kind")
	maxDim, ok := animeImageMaxDim[kind]
	if !ok {
		http.Error(w, `{"error":"kind должен быть poster или banner"}`, http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("image")
	if err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, `{"error":"Файл превышает 5 МБ"}`, http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, `{"error":"Файл (поле image) обязателен"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	tmpPath, err := normalizeUploadedImage(file, maxDim)
	if err != nil {
		http.Error(w, `{"error":"Файл не распознан как изображение (jpg/png/webp)"}`, http.StatusBadRequest)
		return
	}
	defer os.Remove(tmpPath)

	objectName := fmt.Sprintf("anime/%s-%d.jpg", kind, time.Now().UnixNano())
	url, err := uploadSingleFile(r.Context(), tmpPath, objectName, "image/jpeg")
	if err != nil {
		http.Error(w, `{"error":"Ошибка загрузки в хранилище"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "url": url})
}

// apiAdminEpisodeImageUpload — POST /api/admin/episode/image, multipart с
// полями episode_id и image. Та же схема, что apiAdminAnimeImageUpload, но
// пишет сразу в episodes.poster_url (без промежуточного save-запроса).
func apiAdminEpisodeImageUpload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	adminID, err := getUserIDFromSession(r)
	if err != nil || !isUserAdmin(adminID) {
		http.Error(w, `{"error":"Доступ запрещён"}`, http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAvatarBytes)
	episodeID, err := strconv.Atoi(r.FormValue("episode_id"))
	if err != nil || episodeID == 0 {
		http.Error(w, `{"error":"episode_id обязателен"}`, http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("image")
	if err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, `{"error":"Файл превышает 5 МБ"}`, http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, `{"error":"Файл (поле image) обязателен"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	tmpPath, err := normalizeUploadedImage(file, animeImageMaxDim["poster"])
	if err != nil {
		http.Error(w, `{"error":"Файл не распознан как изображение (jpg/png/webp)"}`, http.StatusBadRequest)
		return
	}
	defer os.Remove(tmpPath)

	objectName := fmt.Sprintf("episodes/poster-%d-%d.jpg", episodeID, time.Now().UnixNano())
	url, err := uploadSingleFile(r.Context(), tmpPath, objectName, "image/jpeg")
	if err != nil {
		http.Error(w, `{"error":"Ошибка загрузки в хранилище"}`, http.StatusInternalServerError)
		return
	}

	if _, err := db.Exec("UPDATE episodes SET poster_url = ? WHERE id = ?", url, episodeID); err != nil {
		http.Error(w, `{"error":"Ошибка сохранения"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "url": url})
}

// apiAdminAnimeDelete — POST /api/admin/anime/delete. Удаляет аниме и
// каскадом все его эпизоды (FK ON DELETE CASCADE, см. deploy/mysql/schema.sql).
func apiAdminAnimeDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	adminID, err := getUserIDFromSession(r)
	if err != nil || !isUserAdmin(adminID) {
		http.Error(w, `{"error":"Доступ запрещён"}`, http.StatusForbidden)
		return
	}
	var body struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == 0 {
		http.Error(w, `{"error":"id обязателен"}`, http.StatusBadRequest)
		return
	}
	if _, err := db.Exec("DELETE FROM anime WHERE id = ?", body.ID); err != nil {
		http.Error(w, `{"error":"ошибка удаления"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// apiAdminEpisodeUpsert — POST /api/admin/episode/save. Метаданные эпизода
// без видео (video_url трогает только adminUploadVideoHandler — там же
// транскодирование и заливка в MinIO). body.ID == 0 создаёт новый эпизод.
func apiAdminEpisodeUpsert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	adminID, err := getUserIDFromSession(r)
	if err != nil || !isUserAdmin(adminID) {
		http.Error(w, `{"error":"Доступ запрещён"}`, http.StatusForbidden)
		return
	}
	var b struct {
		ID         int    `json:"id"`
		AnimeID    int    `json:"anime_id"`
		EpisodeNum int    `json:"episode_num"`
		Season     int    `json:"season"`
		Title      string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.AnimeID == 0 || b.EpisodeNum == 0 || strings.TrimSpace(b.Title) == "" {
		http.Error(w, `{"error":"anime_id, episode_num и title обязательны"}`, http.StatusBadRequest)
		return
	}
	if b.Season == 0 {
		b.Season = 1
	}

	if b.ID == 0 {
		res, err := db.Exec("INSERT INTO episodes (anime_id, episode_num, season, title) VALUES (?, ?, ?, ?)",
			b.AnimeID, b.EpisodeNum, b.Season, b.Title)
		if err != nil {
			http.Error(w, `{"error":"эпизод с таким номером уже существует"}`, http.StatusBadRequest)
			return
		}
		id, _ := res.LastInsertId()
		json.NewEncoder(w).Encode(map[string]int{"id": int(id)})
		return
	}

	if _, err := db.Exec("UPDATE episodes SET episode_num=?, season=?, title=? WHERE id = ? AND anime_id = ?",
		b.EpisodeNum, b.Season, b.Title, b.ID, b.AnimeID); err != nil {
		http.Error(w, `{"error":"ошибка сохранения"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]int{"id": b.ID})
}

// apiAdminEpisodeDelete — POST /api/admin/episode/delete.
func apiAdminEpisodeDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	adminID, err := getUserIDFromSession(r)
	if err != nil || !isUserAdmin(adminID) {
		http.Error(w, `{"error":"Доступ запрещён"}`, http.StatusForbidden)
		return
	}
	var body struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == 0 {
		http.Error(w, `{"error":"id обязателен"}`, http.StatusBadRequest)
		return
	}
	if _, err := db.Exec("DELETE FROM episodes WHERE id = ?", body.ID); err != nil {
		http.Error(w, `{"error":"ошибка удаления"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// adminAchievementStat — процент разблокировки одной ачивки из статического
// каталога achievements (см. выше) среди всех пользователей.
type adminAchievementStat struct {
	Achievement
	UnlockedCount int
	Percent       int
}

// adminFriendshipRow — одна принятая дружба на /admin/community.
type adminFriendshipRow struct {
	RequesterUsername string
	AddresseeUsername string
	CreatedAt         string
}

const adminCommunityPageSize = 25

// adminCommunityHandler — GET /admin/community. Процент разблокировки каждой
// ачивки из каталога + список принятых дружб с поиском по имени и пагинацией.
func adminCommunityHandler(w http.ResponseWriter, r *http.Request) {
	adminUserID := requireAdminPage(w, r)
	if adminUserID == 0 {
		return
	}

	var totalUsers int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalUsers)

	achievementStats := make([]adminAchievementStat, len(achievements))
	for i, a := range achievements {
		var count int
		db.QueryRow("SELECT COUNT(*) FROM user_achievements WHERE achievement_id = ?", a.ID).Scan(&count)
		percent := 0
		if totalUsers > 0 {
			percent = count * 100 / totalUsers
		}
		achievementStats[i] = adminAchievementStat{Achievement: a, UnlockedCount: count, Percent: percent}
	}
	sort.Slice(achievementStats, func(i, j int) bool { return achievementStats[i].UnlockedCount > achievementStats[j].UnlockedCount })

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * adminCommunityPageSize

	where := "WHERE f.status = 'accepted'"
	args := []interface{}{}
	if q != "" {
		where += " AND (ur.username LIKE ? OR ua.username LIKE ?)"
		args = append(args, "%"+q+"%", "%"+q+"%")
	}

	var totalFriendships int
	db.QueryRow(`
		SELECT COUNT(*) FROM friendships f
		JOIN users ur ON ur.id = f.requester_id
		JOIN users ua ON ua.id = f.addressee_id
		`+where, args...).Scan(&totalFriendships)

	rowsArgs := append(append([]interface{}{}, args...), adminCommunityPageSize, offset)
	rows, err := db.Query(`
		SELECT ur.username, ua.username, f.created_at
		FROM friendships f
		JOIN users ur ON ur.id = f.requester_id
		JOIN users ua ON ua.id = f.addressee_id
		`+where+`
		ORDER BY f.created_at DESC
		LIMIT ? OFFSET ?
	`, rowsArgs...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var friendships []adminFriendshipRow
	for rows.Next() {
		var f adminFriendshipRow
		var createdAt sql.NullTime
		if rows.Scan(&f.RequesterUsername, &f.AddresseeUsername, &createdAt) == nil {
			if createdAt.Valid {
				f.CreatedAt = createdAt.Time.Format("02.01.2006")
			}
			friendships = append(friendships, f)
		}
	}

	totalPages := (totalFriendships + adminCommunityPageSize - 1) / adminCommunityPageSize
	if totalPages < 1 {
		totalPages = 1
	}

	username, initial, avatarURL := adminInitial(r, adminUserID)
	data := struct {
		Username         string
		AdminInitial     string
		AdminAvatarURL   string
		AchievementStats []adminAchievementStat
		Friendships      []adminFriendshipRow
		TotalFriendships int
		Query            string
		Page             int
		TotalPages       int
	}{
		Username: username, AdminInitial: initial, AdminAvatarURL: avatarURL,
		AchievementStats: achievementStats, Friendships: friendships,
		TotalFriendships: totalFriendships, Query: q, Page: page, TotalPages: totalPages,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "admin_community.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// adminUploadVideoHandler принимает сырой видеофайл, транскодирует его в adaptive
// HLS (ffmpeg) и заливает в MinIO. Требует авторизованного пользователя с
// is_admin=1 (роль назначается вручную через SQL, пока нет админ-панели —
// см. 13_Дальнейшие_улучшения).
func adminUploadVideoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if !isUserAdmin(userID) {
		http.Error(w, `{"error":"Forbidden"}`, http.StatusForbidden)
		return
	}

	// Ограничиваем размер тела запроса до парсинга формы — иначе неограниченная
	// загрузка большого файла может исчерпать диск/память ещё до валидации полей.
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)

	animeID, err1 := strconv.Atoi(r.FormValue("anime_id"))
	episodeNum, err2 := strconv.Atoi(r.FormValue("episode_num"))
	title := r.FormValue("title")
	if err1 != nil || err2 != nil || title == "" {
		http.Error(w, `{"error":"anime_id, episode_num и title обязательны"}`, http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("video")
	if err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, `{"error":"Файл превышает допустимый размер"}`, http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, `{"error":"Файл видео (поле video) обязателен"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	if err := sniffVideoContainer(file); err != nil {
		http.Error(w, `{"error":"Файл не распознан как видео-контейнер (mp4/mov/webm/mkv/avi)"}`, http.StatusBadRequest)
		return
	}

	tmpDir, err := os.MkdirTemp("", "ancen-upload-*")
	if err != nil {
		http.Error(w, `{"error":"Ошибка временной директории"}`, http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tmpDir)

	inputPath := filepath.Join(tmpDir, "input"+filepath.Ext(header.Filename))
	dst, err := os.Create(inputPath)
	if err != nil {
		http.Error(w, `{"error":"Ошибка сохранения файла"}`, http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(dst, file); err != nil {
		dst.Close()
		http.Error(w, `{"error":"Ошибка записи файла"}`, http.StatusInternalServerError)
		return
	}
	dst.Close()

	outDir := filepath.Join(tmpDir, "hls")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		http.Error(w, `{"error":"Ошибка HLS-директории"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("Транскодирую видео anime_id=%d episode_num=%d...", animeID, episodeNum)
	if err := transcodeToHLS(inputPath, outDir); err != nil {
		log.Println("ffmpeg error:", err)
		http.Error(w, `{"error":"Ошибка транскодирования"}`, http.StatusInternalServerError)
		return
	}

	objectPrefix := fmt.Sprintf("anime/%d/episode/%d", animeID, episodeNum)
	masterURL, err := uploadDir(r.Context(), outDir, objectPrefix)
	if err != nil {
		log.Println("MinIO upload error:", err)
		http.Error(w, `{"error":"Ошибка загрузки в MinIO"}`, http.StatusInternalServerError)
		return
	}

	var episodeID int
	err = db.QueryRow("SELECT id FROM episodes WHERE anime_id = ? AND episode_num = ?", animeID, episodeNum).Scan(&episodeID)
	if err == sql.ErrNoRows {
		res, err := db.Exec("INSERT INTO episodes (anime_id, episode_num, title, video_url) VALUES (?, ?, ?, ?)", animeID, episodeNum, title, masterURL)
		if err != nil {
			http.Error(w, `{"error":"Ошибка записи в БД"}`, http.StatusInternalServerError)
			return
		}
		id, _ := res.LastInsertId()
		episodeID = int(id)
	} else if err != nil {
		http.Error(w, `{"error":"Ошибка запроса к БД"}`, http.StatusInternalServerError)
		return
	} else {
		if _, err := db.Exec("UPDATE episodes SET video_url = ?, title = ? WHERE id = ?", masterURL, title, episodeID); err != nil {
			http.Error(w, `{"error":"Ошибка обновления БД"}`, http.StatusInternalServerError)
			return
		}
	}

	fmt.Fprintf(w, `{"episode_id":%d,"video_url":%q}`, episodeID, masterURL)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

	if c, err := r.Cookie("refresh_token"); err == nil && c.Value != "" {
		auth.RevokeRefreshToken(db, c.Value)
	}
	clearAuthCookies(w, secure)

	session, _ := store.Get(r, "ancen-session")
	session.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// apiAuthRefreshHandler — POST /api/auth/refresh: ротирует refresh-токен из
// cookie refresh_token и выдаёт новую пару access/refresh. Работает только в
// режиме AUTH_MODE=jwt.
func apiAuthRefreshHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if auth.CurrentMode() != auth.ModeJWT {
		http.Error(w, `{"error":"AUTH_MODE=jwt required"}`, http.StatusNotImplemented)
		return
	}
	c, err := r.Cookie("refresh_token")
	if err != nil || c.Value == "" {
		http.Error(w, `{"error":"Missing refresh_token"}`, http.StatusUnauthorized)
		return
	}

	newRefreshToken, userID, err := auth.RotateRefreshToken(db, c.Value)
	if err != nil {
		http.Error(w, `{"error":"Invalid refresh token"}`, http.StatusUnauthorized)
		return
	}
	accessToken, err := auth.IssueAccessToken(userID, isUserAdmin(userID))
	if err != nil {
		http.Error(w, `{"error":"Ошибка выдачи токена"}`, http.StatusInternalServerError)
		return
	}

	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	setAuthCookies(w, secure, accessToken, newRefreshToken)
	fmt.Fprintf(w, `{"access_token":%q}`, accessToken)
}

// apiAuthLogoutHandler — POST /api/auth/logout: отзывает refresh-токен и
// чистит JWT-cookie. Работает только в режиме AUTH_MODE=jwt.
func apiAuthLogoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie("refresh_token"); err == nil && c.Value != "" {
		auth.RevokeRefreshToken(db, c.Value)
	}
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	clearAuthCookies(w, secure)
	fmt.Fprint(w, `{"status":"ok"}`)
}

func apiProgressPost(w http.ResponseWriter, r *http.Request) {
	log.Println("apiProgressPost called")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		EpisodeID    int `json:"episode_id"`
		TimestampSec int `json:"timestamp_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if req.EpisodeID == 0 || req.TimestampSec < 0 {
		http.Error(w, `{"error":"Missing fields"}`, http.StatusBadRequest)
		return
	}

	// watched_seconds защищает от перемотки в конец ради накрутки "досмотрел":
	// плеер шлёт хартбит раз в 5с (см. watch.html), поэтому легитимный прирост
	// между двумя хартбитами не превышает ~5-7с. Прыжок таймкода (перемотка
	// вперёд) даёт большую дельту — засчитываем не больше потолка, остаток
	// прироста просто не учитывается в watched_seconds (last_timestamp_sec
	// при этом всё равно обновляется как обычно — resume-позиция не страдает).
	var prevTimestamp, watchedSeconds int
	err = db.QueryRow("SELECT last_timestamp_sec, watched_seconds FROM user_progress WHERE user_id = ? AND episode_id = ?", userID, req.EpisodeID).
		Scan(&prevTimestamp, &watchedSeconds)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	delta := req.TimestampSec - prevTimestamp
	if delta > 0 {
		if delta > progressHeartbeatCreditCap {
			delta = progressHeartbeatCreditCap
		}
		watchedSeconds += delta
	}

	_, err = db.Exec(`
		INSERT INTO user_progress (user_id, episode_id, last_timestamp_sec, watched_seconds)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE last_timestamp_sec = VALUES(last_timestamp_sec), watched_seconds = VALUES(watched_seconds)
	`, userID, req.EpisodeID, req.TimestampSec, watchedSeconds)
	if err != nil {
		log.Println("DB error in progress save:", err)
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, `{"status":"ok"}`)
}

func apiProgressGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	episodeIDStr := r.URL.Query().Get("episode_id")
	if episodeIDStr == "" {
		http.Error(w, `{"error":"episode_id required"}`, http.StatusBadRequest)
		return
	}
	episodeID, err := strconv.Atoi(episodeIDStr)
	if err != nil {
		http.Error(w, `{"error":"invalid episode_id"}`, http.StatusBadRequest)
		return
	}
	var timestamp int
	err = db.QueryRow(`
		SELECT last_timestamp_sec FROM user_progress
		WHERE user_id = ? AND episode_id = ?
	`, userID, episodeID).Scan(&timestamp)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println("No progress for user", userID, "episode", episodeID)
			fmt.Fprint(w, `{"timestamp_sec":0}`)
			return
		}
		log.Println("DB error:", err)
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	log.Printf("Returning timestamp %d for user %d episode %d", timestamp, userID, episodeID)
	fmt.Fprintf(w, `{"timestamp_sec":%d}`, timestamp)
}

func apiProgressDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodDelete {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		EpisodeID int `json:"episode_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
		return
	}
	_, err = db.Exec("DELETE FROM user_progress WHERE user_id = ? AND episode_id = ?", userID, req.EpisodeID)
	if err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

// ---------- API для ачивок ----------

func apiAchievementsGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	userAchievements := getUserAchievements(userID)
	json.NewEncoder(w).Encode(userAchievements)
}

// apiUserAvatarGet отдаёт avatar_url текущего пользователя — используется
// header.html, чтобы показать реальный аватар вместо буквы-заглушки без
// протаскивания AvatarURL через каждый page-handler отдельно.
func apiUserAvatarGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var avatarURL string
	db.QueryRow("SELECT avatar_url FROM users WHERE id = ?", userID).Scan(&avatarURL)
	json.NewEncoder(w).Encode(map[string]string{"avatar_url": avatarURL})
}

func apiLevelGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var xp int
	err = db.QueryRow("SELECT xp FROM user_xp WHERE user_id = ?", userID).Scan(&xp)
	if err != nil {
		xp = 0
	}

	levelInfo := getLevelInfo(xp)
	json.NewEncoder(w).Encode(levelInfo)
}

func apiFriendsGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(getFriends(userID))
}

// apiPartyDeclineHandler — отклонение приглашения на синхропросмотр из
// шапки. /ws/dm (которым доставляется само приглашение) push-only, сервер
// не читает по нему входящие сообщения — поэтому отклонение идёт через REST,
// не через WS, в отличие от остальной party-логики на watch.html.
func apiPartyDeclineHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		PartyID string `json:"party_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PartyID == "" {
		http.Error(w, `{"error":"party_id обязателен"}`, http.StatusBadRequest)
		return
	}
	if hostID, ok := partyH.hostOf(req.PartyID); ok {
		sendToUser(hostID, WsMessage{Type: "party_declined", PartyID: req.PartyID, UserID: userID})
		partyH.cancel(req.PartyID)
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func apiFriendRequestsGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(getPendingIncoming(userID))
}

func apiFriendRequestPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var body struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Username == "" {
		http.Error(w, `{"error":"username required"}`, http.StatusBadRequest)
		return
	}
	status, err := sendFriendRequest(userID, body.Username)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": status})
}

func apiFriendRespondPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var body struct {
		RequestID int    `json:"request_id"`
		Action    string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.Action != "accept" && body.Action != "decline") {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if err := respondFriendRequest(userID, body.RequestID, body.Action == "accept"); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	var newAchievements []Achievement
	if body.Action == "accept" {
		newAchievements = checkAndUnlockAchievements(userID)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "achievements": newAchievements})
}

func apiFriendRemovePost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var body struct {
		UserID int `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.UserID == 0 {
		http.Error(w, `{"error":"user_id required"}`, http.StatusBadRequest)
		return
	}
	if err := removeFriendship(userID, body.UserID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// apiUsersSearchGet ищет пользователей по имени — для вкладки "Друзья" в поиске хедера.
func apiUsersSearchGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		json.NewEncoder(w).Encode([]FriendInfo{})
		return
	}
	viewerID, _ := getUserIDFromSession(r)
	rows, err := db.Query(`
		SELECT u.id, u.username, u.avatar_url, u.avatar_frame, COALESCE(ux.xp, 0)
		FROM users u
		LEFT JOIN user_xp ux ON ux.user_id = u.id
		WHERE u.username LIKE ? AND u.id != ?
		ORDER BY u.username
		LIMIT 10
	`, "%"+q+"%", viewerID)
	if err != nil {
		http.Error(w, `{"error":"search failed"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(friendInfoRows(rows))
}

// apiAnimeSearchGet — поиск аниме по названию для выпадающего списка в шапке.
func apiAnimeSearchGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	type AnimeResult struct {
		ID     int    `json:"id"`
		Title  string `json:"title"`
		Genres string `json:"genres"`
		Year   string `json:"year"`
		Poster string `json:"poster"`
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		json.NewEncoder(w).Encode([]AnimeResult{})
		return
	}
	rows, err := db.Query(`
		SELECT id, title, genres, year, poster_url FROM anime
		WHERE title LIKE ? ORDER BY title LIMIT 8
	`, "%"+q+"%")
	if err != nil {
		http.Error(w, `{"error":"search failed"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	results := []AnimeResult{}
	for rows.Next() {
		var a AnimeResult
		if rows.Scan(&a.ID, &a.Title, &a.Genres, &a.Year, &a.Poster) == nil {
			results = append(results, a)
		}
	}
	json.NewEncoder(w).Encode(results)
}

// apiFavoriteAnimeToggle переключает избранное аниме для текущего пользователя.
func apiFavoriteAnimeToggle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var body struct {
		AnimeID int `json:"anime_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AnimeID == 0 {
		http.Error(w, `{"error":"anime_id required"}`, http.StatusBadRequest)
		return
	}
	var exists int
	db.QueryRow("SELECT COUNT(*) FROM favorites WHERE user_id = ? AND anime_id = ?", userID, body.AnimeID).Scan(&exists)
	if exists > 0 {
		db.Exec("DELETE FROM favorites WHERE user_id = ? AND anime_id = ?", userID, body.AnimeID)
		json.NewEncoder(w).Encode(map[string]bool{"active": false})
		return
	}
	if _, err := db.Exec("INSERT INTO favorites (user_id, anime_id) VALUES (?, ?)", userID, body.AnimeID); err != nil {
		http.Error(w, `{"error":"anime not found"}`, http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]bool{"active": true})
}

// apiFavoriteEpisodeToggle переключает "буду смотреть" для эпизода.
func apiFavoriteEpisodeToggle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var body struct {
		EpisodeID int `json:"episode_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.EpisodeID == 0 {
		http.Error(w, `{"error":"episode_id required"}`, http.StatusBadRequest)
		return
	}
	var exists int
	db.QueryRow("SELECT COUNT(*) FROM favorite_episodes WHERE user_id = ? AND episode_id = ?", userID, body.EpisodeID).Scan(&exists)
	if exists > 0 {
		db.Exec("DELETE FROM favorite_episodes WHERE user_id = ? AND episode_id = ?", userID, body.EpisodeID)
		json.NewEncoder(w).Encode(map[string]bool{"active": false})
		return
	}
	if _, err := db.Exec("INSERT INTO favorite_episodes (user_id, episode_id) VALUES (?, ?)", userID, body.EpisodeID); err != nil {
		http.Error(w, `{"error":"episode not found"}`, http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]bool{"active": true})
}

func apiAllAchievementsGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, err := getUserIDFromSession(r)
	unlocked := make(map[string]bool)
	if err == nil {
		rows, err := db.Query("SELECT achievement_id FROM user_achievements WHERE user_id = ?", userID)
		if err == nil {
			for rows.Next() {
				var id string
				rows.Scan(&id)
				unlocked[id] = true
			}
			rows.Close()
		}
	}

	type AchievementWithStatus struct {
		Achievement
		Unlocked bool `json:"unlocked"`
	}

	result := make([]AchievementWithStatus, len(achievements))
	for i, a := range achievements {
		result[i] = AchievementWithStatus{
			Achievement: a,
			Unlocked:    unlocked[a.ID],
		}
	}

	json.NewEncoder(w).Encode(result)
}

// ---------- ВОССТАНОВЛЕНИЕ ПАРОЛЯ ----------

// generateResetToken генерирует криптостойкий токен
func generateResetToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// sendPasswordResetEmail генерирует токен сброса пароля для userID/email и
// отправляет письмо со ссылкой на /new-password. Используется и восстановлением
// пароля (forgotPasswordHandler), и сменой пароля из личного кабинета.
func sendPasswordResetEmail(userID int, email string) error {
	token, err := generateResetToken()
	if err != nil {
		return err
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	if _, err := db.Exec(
		"INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)",
		userID, token, expiresAt,
	); err != nil {
		return err
	}

	from := os.Getenv("SMTP_FROM")
	password := os.Getenv("SMTP_PASS")
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")

	resetLink := fmt.Sprintf("http://localhost:8080/new-password?token=%s", token)
	subject := "Subject: Смена пароля на AniMemory\r\n"
	mime := "MIME-version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n"
	body := fmt.Sprintf(`
		<h2>Смена пароля</h2>
		<p>Перейдите по ссылке ниже, чтобы задать новый пароль:</p>
		<p><a href="%s">%s</a></p>
		<p>Ссылка действительна 1 час.</p>
		<p>Если вы не запрашивали смену пароля, проигнорируйте это письмо.</p>
	`, resetLink, resetLink)
	headers := fmt.Sprintf("From: %s\r\nTo: %s\r\n", from, email)
	headers += "X-Priority: 1\r\nX-Mailer: AniMemory\r\n"
	fullMsg := []byte(headers + subject + mime + body)

	auth := smtp.PlainAuth("", from, password, smtpHost)
	return smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{email}, fullMsg)
}

// apiRequestPasswordChangeHandler — POST /api/profile/request-password-change.
// Требует авторизации: отправляет на привязанную почту ссылку для смены пароля,
// без необходимости помнить старый пароль ("забыли пароль" — тот же токен-флоу,
// но инициированный самим пользователем из профиля).
func apiRequestPasswordChangeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var email string
	if err := db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&email); err != nil {
		http.Error(w, "Пользователь не найден", http.StatusNotFound)
		return
	}

	if !actionLimiter.allow("forgot:"+clientIP(r), forgotPasswordRateLimit, forgotPasswordRateWindow) ||
		!actionLimiter.allow("forgot:"+strings.ToLower(email), forgotPasswordRateLimit, forgotPasswordRateWindow) {
		http.Error(w, "Слишком много запросов, попробуйте позже", http.StatusTooManyRequests)
		return
	}

	if err := sendPasswordResetEmail(userID, email); err != nil {
		log.Printf("change-password email error: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true,"message":"Ссылка для смены пароля отправлена на вашу почту"}`))
}

// forgotPasswordHandler — GET/POST /forgot-password
func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		if email == "" {
			render(w, "forgot-password.html", PageData{Title: "Восстановление пароля", Error: "Введите email"})
			return
		}

		if !actionLimiter.allow("forgot:"+clientIP(r), forgotPasswordRateLimit, forgotPasswordRateWindow) ||
			!actionLimiter.allow("forgot:"+strings.ToLower(email), forgotPasswordRateLimit, forgotPasswordRateWindow) {
			// Тот же нейтральный ответ, что и при несуществующем email — не палим наличие лимита
			render(w, "forgot-password.html", PageData{Title: "Восстановление пароля", Success: "На вашу почту отправлено сообщение для сброса пароля."})
			return
		}

		// Ищем пользователя по email (в таблице users поле username хранит email)
		var userID int
		err := db.QueryRow("SELECT id FROM users WHERE username = ?", email).Scan(&userID)
		if err != nil {
			// Не показываем, существует пользователь или нет — безопасность
			render(w, "forgot-password.html", PageData{Title: "Восстановление пароля", Success: "На вашу почту отправлено сообщение для сброса пароля."})
			return
		}

		// Генерируем токен
		token, err := generateResetToken()
		if err != nil {
			render(w, "forgot-password.html", PageData{Title: "Восстановление пароля", Error: "Ошибка генерации токена"})
			return
		}

		// Сохраняем в БД (токен живёт 1 час)
		expiresAt := time.Now().Add(1 * time.Hour)
		_, err = db.Exec(
			"INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)",
			userID, token, expiresAt,
		)
		if err != nil {
			log.Printf("password_resets insert error: %v", err)
			render(w, "forgot-password.html", PageData{Title: "Восстановление пароля", Error: "Ошибка БД"})
			return
		}

		// Отправляем email
		from := os.Getenv("SMTP_FROM")
		password := os.Getenv("SMTP_PASS")
		smtpHost := os.Getenv("SMTP_HOST")
		smtpPort := os.Getenv("SMTP_PORT")

		resetLink := fmt.Sprintf("http://localhost:8080/new-password?token=%s", token)
		subject := "Subject: Восстановление пароля на AniMemory\r\n"
		mime := "MIME-version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n"
		body := fmt.Sprintf(`
			<h2>Восстановление пароля</h2>
			<p>Вы запросили сброс пароля на AniMemory.</p>
			<p>Перейдите по ссылке ниже, чтобы задать новый пароль:</p>
			<p><a href="%s">%s</a></p>
			<p>Ссылка действительна 1 час.</p>
			<p>Если вы не запрашивали сброс пароля, проигнорируйте это письмо.</p>
		`, resetLink, resetLink)
		// Добавляем заголовки для anti-spam
		headers := fmt.Sprintf("From: %s\r\nTo: %s\r\n", from, email)
		headers += "X-Priority: 1\r\nX-Mailer: AniMemory\r\n"
		fullMsg := []byte(headers + subject + mime + body)

		auth := smtp.PlainAuth("", from, password, smtpHost)
		err = smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{email}, fullMsg)
		if err != nil {
			log.Printf("Email send error: %v", err)
			// Всё равно показываем успех — не раскрываем существование email
		}

		render(w, "forgot-password.html", PageData{Title: "Восстановление пароля", Success: "На вашу почту отправлено сообщение для сброса пароля."})
		return
	}
	render(w, "forgot-password.html", PageData{Title: "Восстановление пароля"})
}

// newPasswordHandler — GET/POST /new-password
func newPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		token := r.FormValue("token")
		password := r.FormValue("password")
		passwordConfirm := r.FormValue("password_confirm")

		if token == "" || password == "" || passwordConfirm == "" {
			render(w, "new-password.html", PageData{Title: "Смена пароля", Error: "Заполните все поля"})
			return
		}

		if password != passwordConfirm {
			render(w, "new-password.html", PageData{Title: "Смена пароля", Error: "Пароли не совпадают"})
			return
		}

		if len(password) < 6 {
			render(w, "new-password.html", PageData{Title: "Смена пароля", Error: "Пароль должен быть не менее 6 символов"})
			return
		}

		// Проверяем токен
		var userID int
		var expiresAt time.Time
		err := db.QueryRow(
			"SELECT user_id, expires_at FROM password_resets WHERE token = ? AND used = 0",
			token,
		).Scan(&userID, &expiresAt)
		if err != nil {
			render(w, "new-password.html", PageData{Title: "Смена пароля", Error: "Неверный или использованный токен"})
			return
		}

		if time.Now().After(expiresAt) {
			render(w, "new-password.html", PageData{Title: "Смена пароля", Error: "Срок действия ссылки истёк. Запросите сброс пароля заново."})
			return
		}

		// Хешируем новый пароль
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
		if err != nil {
			render(w, "new-password.html", PageData{Title: "Смена пароля", Error: "Ошибка хеширования пароля"})
			return
		}

		// Обновляем пароль
		_, err = db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hashedPassword), userID)
		if err != nil {
			render(w, "new-password.html", PageData{Title: "Смена пароля", Error: "Ошибка БД"})
			return
		}

		// Помечаем токен как использованный
		_, _ = db.Exec("UPDATE password_resets SET used = 1 WHERE token = ?", token)

		// Удаляем все старые токены для этого пользователя
		_, _ = db.Exec("UPDATE password_resets SET used = 1 WHERE user_id = ?", userID)

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// GET — показываем форму с токеном из query
	token := r.URL.Query().Get("token")
	data := struct {
		Title   string
		Error   string
		Success string
		Token   string
	}{
		Title: "Смена пароля",
		Token: token,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := templates.ExecuteTemplate(w, "new-password.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ---------- Запуск сервера ----------
func main() {
	godotenv.Load()
	dsn := os.Getenv("DB_USER") + ":" + os.Getenv("DB_PASS") + "@tcp(" + os.Getenv("DB_HOST") + ":" + os.Getenv("DB_PORT") + ")/" + os.Getenv("DB_NAME") + "?charset=utf8mb4&parseTime=true"
	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))

	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Ошибка подключения к БД:", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatal("БД не отвечает:", err)
	}
	log.Println("Подключено к MySQL")

	// Создаём таблицы для системы ачивок
	createTables()

	var maintenanceOn bool
	db.QueryRow("SELECT maintenance_mode FROM app_settings WHERE id = 1").Scan(&maintenanceOn)
	maintenanceMode.Store(maintenanceOn)

	if err := auth.LoadKeys(); err != nil {
		log.Fatal("Ошибка загрузки JWT-ключей:", err)
	}
	if err := loadEmailEncryptionKey(); err != nil {
		log.Fatal("Ошибка загрузки ключа шифрования email:", err)
	}

	initMinioClient()

	go hub.run()

	// Регистрация маршрутов
	secureHandle("/", homeHandler)
	secureHandle("/login", loginHandler)
	secureHandle("/register", registerHandler)
	secureHandle("/anime/", animeHandler)
	secureHandle("/watch", watchHandler)
	secureHandle("/profile", profileHandler)
	secureHandle("/premium", premiumHandler)
	secureHandle("/privacy-policy", privacyPolicyHandler)
	secureHandle("/terms", termsHandler)
	secureHandle("/api/emotion", apiEmotionPost)
	secureHandle("/api/emotions", apiEmotionsGet)
	secureHandle("/ws", wsHandler)
	secureHandle("/ws/dm", wsDMHandler)
	secureHandle("/api/emotions/stats", apiEmotionsStats)
	secureHandle("/api/comment", apiCommentPost)
	secureHandle("/api/comment/voice", apiVoiceCommentPost)
	secureHandle("/api/comments", apiCommentsGet)
	secureHandle("/api/comments/like", apiCommentLikeToggle)
	secureHandle("/search", searchHandler)
	secureHandle("/forgot-password", forgotPasswordHandler)
	secureHandle("/new-password", newPasswordHandler)
	secureHandle("/logout", logoutHandler)
	secureHandle("/robots.txt", robotsHandler)
	secureHandle("/sitemap.xml", sitemapHandler)
	secureHandle("/api/progress", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			apiProgressPost(w, r)
		case http.MethodGet:
			apiProgressGet(w, r)
		case http.MethodDelete:
			apiProgressDelete(w, r)
		default:
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})
	// API для ачивок
	secureHandle("/api/achievements", apiAchievementsGet)
	secureHandle("/api/level", apiLevelGet)
	secureHandle("/api/user/avatar", apiUserAvatarGet)
	secureHandle("/api/achievements/all", apiAllAchievementsGet)
	secureHandle("/admin", adminDashboardHandler)
	secureHandle("/admin/users", adminUsersHandler)
	secureHandle("/api/admin/users/toggle", apiAdminUserToggle)
	secureHandle("/api/admin/users", apiAdminUsersList)
	secureHandle("/admin/analytics", adminAnalyticsHandler)
	secureHandle("/admin/settings", adminSettingsHandler)
	secureHandle("/api/admin/settings/maintenance", apiAdminMaintenanceToggle)
	secureHandle("/admin/catalog", adminCatalogHandler)
	secureHandle("/admin/catalog/anime", adminAnimeDetailHandler)
	secureHandle("/admin/community", adminCommunityHandler)
	secureHandle("/api/admin/anime/save", apiAdminAnimeUpsert)
	secureHandle("/api/admin/anime/image", apiAdminAnimeImageUpload)
	secureHandle("/api/admin/episode/image", apiAdminEpisodeImageUpload)
	secureHandle("/api/admin/anime/delete", apiAdminAnimeDelete)
	secureHandle("/api/admin/episode/save", apiAdminEpisodeUpsert)
	secureHandle("/api/admin/episode/delete", apiAdminEpisodeDelete)
	secureHandle("/api/admin/upload-video", adminUploadVideoHandler)
	secureHandle("/api/profile/avatar", apiAvatarUploadHandler)
	secureHandle("/api/profile/background", apiBackgroundUploadHandler)
	secureHandle("/api/profile/background/remove", apiBackgroundRemoveHandler)
	secureHandle("/api/profile/watching-activity", apiWatchingActivityToggleHandler)
	secureHandle("/api/profile/dm-privacy", apiDmPrivacyToggle)
	secureHandle("/messages", messagesHandler)
	secureHandle("/api/messages", apiMessagesGet)
	secureHandle("/api/messages/send", apiMessageSend)
	secureHandle("/api/messages/read", apiMessagesMarkRead)
	secureHandle("/api/messages/read-one", apiMessageReadOne)
	secureHandle("/api/messages/unread-count", apiUnreadMessagesCount)
	secureHandle("/api/conversations", apiConversationsList)
	secureHandle("/api/retention-progress", apiRetentionProgressHandler)
	secureHandle("/api/profile/avatar-frame", apiAvatarFrameHandler)
	secureHandle("/api/profile/chart-color", apiChartColorHandler)
	secureHandle("/api/profile/request-password-change", apiRequestPasswordChangeHandler)
	secureHandle("/api/change-password", apiChangePasswordHandler)
	secureHandle("/api/auth/refresh", apiAuthRefreshHandler)
	secureHandle("/api/auth/logout", apiAuthLogoutHandler)
	secureHandle("/api/user/delete", apiUserDeleteHandler)
	secureHandle("/profile/", profileByUsernameHandler)
	secureHandle("/api/friends", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			apiFriendsGet(w, r)
		case http.MethodPost:
			apiFriendRequestPost(w, r)
		default:
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})
	secureHandle("/api/friends/requests", apiFriendRequestsGet)
	secureHandle("/api/friends/respond", apiFriendRespondPost)
	secureHandle("/api/friends/remove", apiFriendRemovePost)
	secureHandle("/api/party/decline", apiPartyDeclineHandler)
	secureHandle("/api/users/search", apiUsersSearchGet)
	secureHandle("/api/anime/search", apiAnimeSearchGet)
	secureHandle("/api/favorites/anime", apiFavoriteAnimeToggle)
	secureHandle("/api/favorites/episode", apiFavoriteEpisodeToggle)

	log.Println("Сервер Ancen запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", gzipMiddleware(http.DefaultServeMux)))
}
