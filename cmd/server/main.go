package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"

	"Ancen/internal/auth"
)

// bcryptCost — ТЗ требует cost=12 (сильнее дефолтного cost=10 из golang.org/x/crypto).
const bcryptCost = 12

// Глобальные переменные
var db *sql.DB
var templates *template.Template
var store *sessions.CookieStore

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

	registerRateLimit  = 5
	registerRateWindow = time.Hour

	forgotPasswordRateLimit  = 3
	forgotPasswordRateWindow = time.Hour
)

var validEmotions = map[string]bool{
	"❤️": true, "😭": true, "🔥": true, "🤯": true, "🥰": true, "😂": true, "👍": true, "💢": true,
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
	db.QueryRow("SELECT is_premium FROM users WHERE id = ?", userID).Scan(&isPremium)
	return isPremium
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
			"script-src 'self' 'unsafe-inline' https://vjs.zencdn.net",
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://vjs.zencdn.net",
			"font-src 'self' https://fonts.gstatic.com data:",
			"img-src 'self' data: https:",
			"media-src " + mediaSrc + " https://vjs.zencdn.net",
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
	http.HandleFunc(pattern, securityHeaders(csrfProtect(h)))
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
	http.Handle("/static/", http.StripPrefix("/static/", fs))
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
}

// Уровни: сколько всего XP нужно набрать для каждого уровня.
// Кривая квадратичная — первые уровни быстрые (дофамин новичку), дальше резко
// сложнее. При dailyXPCap=150 (см. addXP) набрать максимальный уровень (12)
// быстрее чем за ~75 дней (11284/150) физически невозможно, даже если
// проспамить реакциями — это и есть защита от "прошёл всё за неделю".
// Обычный активный пользователь (без выжимания дневного лимита) наберёт
// макс. уровень за ~2-3 месяца.
var levelXPRequirements = buildLevelXPRequirements(12)

func buildLevelXPRequirements(maxLevel int) []int {
	req := make([]int, maxLevel+1) // index 0 не используется (уровень 0)
	for i := 1; i <= maxLevel; i++ {
		req[i] = req[i-1] + 14*i*i + 28*i
	}
	return req
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
	}
	for _, q := range tables {
		if _, err := db.Exec(q); err != nil {
			log.Printf("createTable error: %v", err)
		}
	}
	log.Println("Таблицы ачивок и сброса пароля проверены/созданы")

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
	// Метаданные для карточки аниме (страна/первоисточник/студия/автор/режиссёр) — из Figma
	for _, col := range []string{"country", "source_type", "studio", "author", "director"} {
		if _, err := db.Exec("ALTER TABLE anime ADD COLUMN " + col + " VARCHAR(255) DEFAULT ''"); err != nil {
			log.Printf("ALTER TABLE anime (%s) может уже существовать: %v", col, err)
		}
	}
	if _, err := db.Exec("ALTER TABLE anime ADD COLUMN year VARCHAR(16) DEFAULT ''"); err != nil {
		log.Printf("ALTER TABLE anime (year) может уже существовать: %v", err)
	}
	// Premium-подписка: без неё реакции/комментарии видны только до текущего прогресса
	// просмотра (анти-спойлер), см. isPremiumUser/watchedUpToSec
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN is_premium TINYINT(1) NOT NULL DEFAULT 0"); err != nil {
		log.Printf("ALTER TABLE users (is_premium) может уже существовать: %v", err)
	}
	// Кастомизация профиля: свой аватар (только Premium — хранение в MinIO стоит денег,
	// см. 18_Монетизация_и_уровни.md) и рамка аватара (пресет, разблокируется уровнем)
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN avatar_url VARCHAR(500) DEFAULT ''"); err != nil {
		log.Printf("ALTER TABLE users (avatar_url) может уже существовать: %v", err)
	}
	if _, err := db.Exec("ALTER TABLE users ADD COLUMN avatar_frame VARCHAR(32) DEFAULT ''"); err != nil {
		log.Printf("ALTER TABLE users (avatar_frame) может уже существовать: %v", err)
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
}

const defaultBackgroundURL = "/static/img/profile/default_bg.jpg"

// ---------- Обработчики ----------

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// "/" зарегистрирован в DefaultServeMux как catch-all: Go отдаёт этот
	// хендлер для ЛЮБОГО пути без отдельного маршрута, так что несуществующие
	// URL нужно ловить здесь и рендерить 404, а не отдавать им главную.
	if r.URL.Path != "/" {
		notFoundHandler(w, r)
		return
	}

	// Отдаём реальный контент главной страницы сразу по "/" (важно для SEO —
	// поисковый робот должен видеть контент без JS-редиректа). Прелоадер
	// показывается как визуальный оверлей внутри home.html и просто гаснет,
	// без навигации на отдельный URL.
	render(w, "home.html", PageData{
		Title:    "AniMemory — смотри аниме и делись эмоциями в реальном времени",
		Username: currentUsername(r),
	})
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
		http.NotFound(w, r)
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
			http.NotFound(w, r)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	rows, err := db.Query("SELECT id, episode_num, season, title FROM episodes WHERE anime_id = ? ORDER BY season, episode_num", id)
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
		if err := rows.Scan(&ep.ID, &ep.Num, &ep.Season, &ep.Title); err != nil {
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
			http.NotFound(w, r)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	// Получаем информацию об уровне пользователя для отображения
	userID, _ := getUserIDFromSession(r)
	levelInfo := UserLevelInfo{}
	if userID > 0 {
		var xp int
		err := db.QueryRow("SELECT xp FROM user_xp WHERE user_id = ?", userID).Scan(&xp)
		if err == nil {
			levelInfo = getLevelInfo(xp)
		}
	}

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
		EpisodeNum    int
		VideoURL      string
		Title         string
		UserLevel     UserLevelInfo
		Username      string
		IsPremium     bool
		AnimeID       int
		PrevEpisodeID int
		NextEpisodeID int
		NextEpisodes  []NextEpisode
		// IntroStart/IntroEnd/OutroStart/OutroEnd: 0 здесь означает "не задано" (NULL в БД),
		// а не "начинается с 0-й секунды" — фронтенду нужно отдельно проверять,
		// заданы ли таймкоды (например, через ненулевой IntroEnd), прежде чем показывать кнопку "Пропустить".
		IntroStart int64
		IntroEnd   int64
		OutroStart int64
		OutroEnd   int64
	}{
		EpisodeNum:    episode.EpisodeNum,
		VideoURL:      episode.VideoURL,
		Title:         episode.Title,
		UserLevel:     levelInfo,
		Username:      currentUsername(r),
		IsPremium:     isPremiumUser(userID),
		AnimeID:       episode.AnimeID,
		PrevEpisodeID: prevEpisodeID,
		NextEpisodeID: nextEpisodeID,
		NextEpisodes:  nextEpisodes,
		IntroStart:    episode.IntroStart.Int64,
		IntroEnd:      episode.IntroEnd.Int64,
		OutroStart:    episode.OutroStart.Int64,
		OutroEnd:      episode.OutroEnd.Int64,
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
		http.NotFound(w, r)
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

	var username, avatarURL, avatarFrame, backgroundURL string
	var isPremium, isBanned bool
	err := db.QueryRow("SELECT username, avatar_url, avatar_frame, is_premium, background_url, is_banned FROM users WHERE id = ?", targetID).
		Scan(&username, &avatarURL, &avatarFrame, &isPremium, &backgroundURL, &isBanned)
	if err != nil {
		http.NotFound(w, r)
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
		Username            string // виewer — для header.html
		ProfileUsername     string // владелец просматриваемого профиля
		ProfileUserID       int
		IsOwnProfile        bool
		FriendshipStatus    string
		FriendshipRequestID int
		Friends             []FriendInfo
		PendingRequests     []FriendRequestInfo
		Level               UserLevelInfo
		AchievementSlots    []AchievementSlot
		EmotionCount        int
		CommentCount        int
		EpisodeCount        int
		ContinueWatching    []ContinueEpisode
		FavoriteAnime       []FavoriteAnime
		AvatarURL           string
		AvatarFrame         string
		AvatarFrameColor    string
		BackgroundURL       string
		IsPremium           bool
		FrameOptions        []FrameOption
		IsViewerAdmin       bool
		IsBanned            bool
	}{
		Username:            viewerUsername,
		ProfileUsername:     username,
		ProfileUserID:       targetID,
		IsOwnProfile:        isOwn,
		FriendshipStatus:    friendshipStatus,
		FriendshipRequestID: friendshipRequestID,
		Friends:             friends,
		PendingRequests:     pendingRequests,
		Level:               levelInfo,
		AchievementSlots:    achievementSlots,
		EmotionCount:        emotionCount,
		CommentCount:        commentCount,
		EpisodeCount:        episodeCount,
		ContinueWatching:    continueWatching,
		FavoriteAnime:       favoriteAnime,
		AvatarURL:           avatarURL,
		AvatarFrame:         avatarFrame,
		AvatarFrameColor:    avatarFrameColor,
		BackgroundURL:       backgroundURL,
		IsPremium:           isPremium,
		FrameOptions:        frameOptions,
		IsViewerAdmin:       !isOwn && isUserAdmin(viewerID),
		IsBanned:            isBanned,
	}

	if err := templates.ExecuteTemplate(w, "profile.html", data); err != nil {
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
	if !validEmotions[req.EmotionType] {
		http.Error(w, `{"error":"Invalid emotion type"}`, http.StatusBadRequest)
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
		SELECT e.emotion_type, e.timestamp_sec, u.username, e.user_id
		FROM emotions e
		JOIN users u ON e.user_id = u.id
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
	}
	emotions := []Emotion{}
	for rows.Next() {
		var e Emotion
		var authorID int
		if err := rows.Scan(&e.EmotionType, &e.TimestampSec, &e.Username, &authorID); err != nil {
			continue
		}
		e.IsFriend = friendIDs[authorID]
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
	register   chan *Client
	unregister chan *Client
	broadcast  chan WsMessage
	mu         sync.RWMutex
}

var hub = &Hub{
	rooms:      make(map[int]map[*Client]bool),
	register:   make(chan *Client),
	unregister: make(chan *Client),
	broadcast:  make(chan WsMessage),
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
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if clients, ok := h.rooms[client.episodeID]; ok {
				delete(clients, client)
				if len(clients) == 0 {
					delete(h.rooms, client.episodeID)
				}
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
		}()
		for {
			var msg WsMessage
			err := conn.ReadJSON(&msg)
			if err != nil {
				log.Println("ReadJSON error:", err)
				break
			}
			log.Printf("📨 Received WS message: type=%s episode_id=%d emotion_type=%s", msg.Type, msg.EpisodeID, msg.EmotionType)
			if msg.Type == "emotion" && msg.EpisodeID == episodeID {
				if !validEmotions[msg.EmotionType] || msg.TimestampSec < 0 {
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
	CreatedAt    string `json:"created_at"`
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
		SELECT c.id, u.username, c.timestamp_sec, c.text, c.created_at
		FROM comments c
		JOIN users u ON c.user_id = u.id
		WHERE c.episode_id = ?`
	args := []interface{}{episodeID}
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
		if err := rows.Scan(&c.ID, &c.Username, &c.TimestampSec, &c.Text, &createdAt); err != nil {
			continue
		}
		if createdAt.Valid {
			c.CreatedAt = createdAt.Time.Format("2006-01-02 15:04:05")
		}
		comments = append(comments, c)
	}
	json.NewEncoder(w).Encode(comments)
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

// sniffImageContainer проверяет magic bytes на JPEG/PNG/WebP — расширение
// файла легко подделать (см. sniffVideoContainer).
func sniffImageContainer(f multipart.File) (ext string, err error) {
	head := make([]byte, 12)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return "", err
	}
	head = head[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	switch {
	case len(head) >= 3 && bytes.Equal(head[:3], []byte{0xFF, 0xD8, 0xFF}):
		return ".jpg", nil
	case len(head) >= 8 && bytes.Equal(head[:8], []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		return ".png", nil
	case len(head) >= 12 && string(head[:4]) == "RIFF" && string(head[8:12]) == "WEBP":
		return ".webp", nil
	}
	return "", fmt.Errorf("unrecognized image signature")
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

// apiAvatarUploadHandler принимает файл аватара — только для Premium-пользователей
// (хранение в MinIO стоит денег, см. 18_Монетизация_и_уровни.md), остальным доступны
// только рамки-пресеты (apiAvatarFrameHandler).
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
	if !isPremiumUser(userID) {
		http.Error(w, `{"error":"Загрузка своего аватара доступна только по подписке Premium"}`, http.StatusForbidden)
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

	ext, err := sniffImageContainer(file)
	if err != nil {
		http.Error(w, `{"error":"Файл не распознан как изображение (jpg/png/webp)"}`, http.StatusBadRequest)
		return
	}

	tmpFile, err := os.CreateTemp("", "ancen-avatar-*"+ext)
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

	objectName := fmt.Sprintf("avatars/%d-%d%s", userID, time.Now().UnixNano(), ext)
	contentType := "image/jpeg"
	if ext == ".png" {
		contentType = "image/png"
	} else if ext == ".webp" {
		contentType = "image/webp"
	}
	url, err := uploadSingleFile(r.Context(), tmpFile.Name(), objectName, contentType)
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
	if !isPremiumUser(userID) {
		http.Error(w, `{"error":"Загрузка своего фона доступна только по подписке Premium"}`, http.StatusForbidden)
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

	ext, err := sniffImageContainer(file)
	if err != nil {
		http.Error(w, `{"error":"Файл не распознан как изображение (jpg/png/webp)"}`, http.StatusBadRequest)
		return
	}

	tmpFile, err := os.CreateTemp("", "ancen-background-*"+ext)
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

	objectName := fmt.Sprintf("backgrounds/%d-%d%s", userID, time.Now().UnixNano(), ext)
	contentType := "image/jpeg"
	if ext == ".png" {
		contentType = "image/png"
	} else if ext == ".webp" {
		contentType = "image/webp"
	}
	url, err := uploadSingleFile(r.Context(), tmpFile.Name(), objectName, contentType)
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

// adminDashboardHandler — GET /admin. Требует is_admin=1 (см. adminUploadVideoHandler).
// Первая итерация Stage 3: только страница метрик, без управления пользователями/аниме.
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

	var totalUsers, premiumUsers, newUsers7d int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalUsers)
	db.QueryRow("SELECT COUNT(*) FROM users WHERE is_premium = 1").Scan(&premiumUsers)
	db.QueryRow("SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL 7 DAY").Scan(&newUsers7d)

	var totalAnime, totalEpisodes int
	db.QueryRow("SELECT COUNT(*) FROM anime").Scan(&totalAnime)
	db.QueryRow("SELECT COUNT(*) FROM episodes").Scan(&totalEpisodes)

	var totalReactions, totalComments, totalAchievements, totalFriendships int
	db.QueryRow("SELECT COUNT(*) FROM emotions").Scan(&totalReactions)
	db.QueryRow("SELECT COUNT(*) FROM comments").Scan(&totalComments)
	db.QueryRow("SELECT COUNT(*) FROM user_achievements").Scan(&totalAchievements)
	db.QueryRow("SELECT COUNT(*) FROM friendships WHERE status = 'accepted'").Scan(&totalFriendships)

	// Реакции по типам — полоса-метрика
	var reactionLabels []string
	var reactionValues []int
	if rows, err := db.Query("SELECT emotion_type, COUNT(*) c FROM emotions GROUP BY emotion_type ORDER BY c DESC"); err == nil {
		for rows.Next() {
			var t string
			var c int
			if rows.Scan(&t, &c) == nil {
				reactionLabels = append(reactionLabels, t)
				reactionValues = append(reactionValues, c)
			}
		}
		rows.Close()
	}

	// Топ-5 аниме по избранному
	var topAnimeLabels []string
	var topAnimeValues []int
	if rows, err := db.Query(`
		SELECT a.title, COUNT(*) c FROM favorites f
		JOIN anime a ON a.id = f.anime_id
		GROUP BY a.id ORDER BY c DESC LIMIT 5
	`); err == nil {
		for rows.Next() {
			var title string
			var c int
			if rows.Scan(&title, &c) == nil {
				topAnimeLabels = append(topAnimeLabels, title)
				topAnimeValues = append(topAnimeValues, c)
			}
		}
		rows.Close()
	}

	// Топ-5 пользователей по XP
	var topXPLabels []string
	var topXPValues []int
	if rows, err := db.Query(`
		SELECT u.username, x.xp FROM user_xp x
		JOIN users u ON u.id = x.user_id
		ORDER BY x.xp DESC LIMIT 5
	`); err == nil {
		for rows.Next() {
			var username string
			var xp int
			if rows.Scan(&username, &xp) == nil {
				topXPLabels = append(topXPLabels, username)
				topXPValues = append(topXPValues, xp)
			}
		}
		rows.Close()
	}

	// Комментарии по дням за последние 14 дней — точки для SVG-графика
	dayCounts := make(map[string]int)
	if rows, err := db.Query(`
		SELECT DATE(created_at) d, COUNT(*) c FROM comments
		WHERE created_at >= NOW() - INTERVAL 14 DAY
		GROUP BY d
	`); err == nil {
		for rows.Next() {
			var d string
			var c int
			if rows.Scan(&d, &c) == nil {
				dayCounts[d] = c
			}
		}
		rows.Close()
	}
	maxDayCount := 1
	dayValues := make([]int, 14)
	for i := 0; i < 14; i++ {
		day := time.Now().AddDate(0, 0, -13+i).Format("2006-01-02")
		dayValues[i] = dayCounts[day]
		if dayValues[i] > maxDayCount {
			maxDayCount = dayValues[i]
		}
	}
	points := ""
	for i, v := range dayValues {
		x := i * 100 / 13
		y := 100 - v*100/maxDayCount
		if i > 0 {
			points += " "
		}
		points += fmt.Sprintf("%d,%d", x, y)
	}

	// Спарклайн новых пользователей за 7 дней — для карточки "Пользователи"
	newUsersDaily := make([]int, 7)
	if rows, err := db.Query(`
		SELECT DATE(created_at) d, COUNT(*) c FROM users
		WHERE created_at >= NOW() - INTERVAL 7 DAY
		GROUP BY d
	`); err == nil {
		byDay := make(map[string]int)
		for rows.Next() {
			var d string
			var c int
			if rows.Scan(&d, &c) == nil {
				byDay[d] = c
			}
		}
		rows.Close()
		for i := 0; i < 7; i++ {
			day := time.Now().AddDate(0, 0, -6+i).Format("2006-01-02")
			newUsersDaily[i] = byDay[day]
		}
	}

	// JSON-снимок для JS-рендера карточек (dashboard.js) — единая точка,
	// куда в будущем добавляются новые метрики без правки шаблона.
	dashboardJSON, err := json.Marshal(map[string]interface{}{
		"users": map[string]interface{}{
			"total": totalUsers, "premium": premiumUsers, "newLast7Days": newUsers7d,
			"sparkline": newUsersDaily,
		},
		"catalog":            map[string]int{"animeCount": totalAnime, "episodes": totalEpisodes},
		"activity":           map[string]int{"reactions": totalReactions, "comments": totalComments},
		"reactionsByType":    buildBarItems(reactionLabels, reactionValues),
		"commentsLast14Days": dayValues,
		"community":          map[string]int{"friendships": totalFriendships, "achievements": totalAchievements},
		"topAnime":           buildBarItems(topAnimeLabels, topAnimeValues),
		"topXP":              buildBarItems(topXPLabels, topXPValues),
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
		DashboardDataJSON template.JS
	}{
		Username:          username,
		AdminInitial:      initial,
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

const adminUsersPageSize = 25

// adminUsersHandler — GET /admin/users. Список пользователей с поиском по
// username и пагинацией; управление ролями идёт через apiAdminUserToggle.
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
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * adminUsersPageSize

	where := ""
	args := []interface{}{}
	if q != "" {
		where = "WHERE u.username LIKE ?"
		args = append(args, "%"+q+"%")
	}

	var total int
	countArgs := append([]interface{}{}, args...)
	db.QueryRow("SELECT COUNT(*) FROM users u "+where, countArgs...).Scan(&total)

	rowsArgs := append(append([]interface{}{}, args...), adminUsersPageSize, offset)
	rows, err := db.Query(`
		SELECT u.id, u.username, COALESCE(ux.xp, 0), u.is_premium, u.is_admin, u.is_banned, u.created_at
		FROM users u
		LEFT JOIN user_xp ux ON ux.user_id = u.id
		`+where+`
		ORDER BY u.id DESC
		LIMIT ? OFFSET ?
	`, rowsArgs...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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

	totalPages := (total + adminUsersPageSize - 1) / adminUsersPageSize
	if totalPages < 1 {
		totalPages = 1
	}

	username := currentUsername(r)
	initial := "?"
	if runes := []rune(username); len(runes) > 0 {
		initial = strings.ToUpper(string(runes[:1]))
	}

	data := struct {
		Username     string
		AdminInitial string
		Users        []adminUserRow
		Query        string
		Page         int
		TotalPages   int
		Total        int
	}{
		Username:     username,
		AdminInitial: initial,
		Users:        users,
		Query:        q,
		Page:         page,
		TotalPages:   totalPages,
		Total:        total,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "admin_users.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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
func adminInitial(r *http.Request) (string, string) {
	username := currentUsername(r)
	initial := "?"
	if runes := []rune(username); len(runes) > 0 {
		initial = strings.ToUpper(string(runes[:1]))
	}
	return username, initial
}

// adminCatalogHandler — GET /admin/catalog. Список аниме с поиском по
// названию, числом эпизодов и постером; добавление/редактирование/удаление —
// через apiAdminAnimeUpsert/apiAdminAnimeDelete.
func adminCatalogHandler(w http.ResponseWriter, r *http.Request) {
	if requireAdminPage(w, r) == 0 {
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

	username, initial := adminInitial(r)
	data := struct {
		Username     string
		AdminInitial string
		Anime        []adminAnimeRow
		Query        string
		Page         int
		TotalPages   int
		Total        int
	}{
		Username: username, AdminInitial: initial,
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
	HasVideo   bool
}

// adminAnimeDetailHandler — GET /admin/catalog/anime?id=. Метаданные аниме
// (форма редактирования) + список его эпизодов с удалением/добавлением.
func adminAnimeDetailHandler(w http.ResponseWriter, r *http.Request) {
	if requireAdminPage(w, r) == 0 {
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
		SELECT id, title, description, poster_url, genres, year, country, source_type, studio, author, director
		FROM anime WHERE id = ?
	`, animeID).Scan(&a.ID, &a.Title, &a.Description, &a.Poster, &a.Genres, &a.Year, &a.Country, &a.SourceType, &a.Studio, &a.Author, &a.Director)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var episodes []adminEpisodeRow
	rows, err := db.Query(`
		SELECT id, episode_num, season, title, video_url
		FROM episodes WHERE anime_id = ? ORDER BY season, episode_num
	`, animeID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e adminEpisodeRow
			var videoURL string
			if rows.Scan(&e.ID, &e.EpisodeNum, &e.Season, &e.Title, &videoURL) == nil {
				e.HasVideo = videoURL != ""
				episodes = append(episodes, e)
			}
		}
	}

	username, initial := adminInitial(r)
	data := struct {
		Username     string
		AdminInitial string
		Anime        animeDetail
		Episodes     []adminEpisodeRow
	}{Username: username, AdminInitial: initial, Anime: a, Episodes: episodes}

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
			INSERT INTO anime (title, description, poster_url, genres, year, country, source_type, studio, author, director)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, b.Title, b.Description, b.Poster, b.Genres, b.Year, b.Country, b.SourceType, b.Studio, b.Author, b.Director)
		if err != nil {
			http.Error(w, `{"error":"ошибка сохранения"}`, http.StatusInternalServerError)
			return
		}
		id, _ := res.LastInsertId()
		json.NewEncoder(w).Encode(map[string]int{"id": int(id)})
		return
	}

	_, err = db.Exec(`
		UPDATE anime SET title=?, description=?, poster_url=?, genres=?, year=?, country=?, source_type=?, studio=?, author=?, director=?
		WHERE id = ?
	`, b.Title, b.Description, b.Poster, b.Genres, b.Year, b.Country, b.SourceType, b.Studio, b.Author, b.Director, b.ID)
	if err != nil {
		http.Error(w, `{"error":"ошибка сохранения"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]int{"id": b.ID})
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
	if requireAdminPage(w, r) == 0 {
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

	username, initial := adminInitial(r)
	data := struct {
		Username          string
		AdminInitial      string
		AchievementStats  []adminAchievementStat
		Friendships       []adminFriendshipRow
		TotalFriendships  int
		Query             string
		Page              int
		TotalPages        int
	}{
		Username: username, AdminInitial: initial,
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
	_, err = db.Exec(`
		INSERT INTO user_progress (user_id, episode_id, last_timestamp_sec)
		VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE last_timestamp_sec = VALUES(last_timestamp_sec)
	`, userID, req.EpisodeID, req.TimestampSec)
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
	secureHandle("/api/emotion", apiEmotionPost)
	secureHandle("/api/emotions", apiEmotionsGet)
	secureHandle("/ws", wsHandler)
	secureHandle("/api/emotions/stats", apiEmotionsStats)
	secureHandle("/api/comment", apiCommentPost)
	secureHandle("/api/comments", apiCommentsGet)
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
	secureHandle("/api/achievements/all", apiAllAchievementsGet)
	secureHandle("/admin", adminDashboardHandler)
	secureHandle("/admin/users", adminUsersHandler)
	secureHandle("/api/admin/users/toggle", apiAdminUserToggle)
	secureHandle("/admin/catalog", adminCatalogHandler)
	secureHandle("/admin/catalog/anime", adminAnimeDetailHandler)
	secureHandle("/admin/community", adminCommunityHandler)
	secureHandle("/api/admin/anime/save", apiAdminAnimeUpsert)
	secureHandle("/api/admin/anime/delete", apiAdminAnimeDelete)
	secureHandle("/api/admin/episode/save", apiAdminEpisodeUpsert)
	secureHandle("/api/admin/episode/delete", apiAdminEpisodeDelete)
	secureHandle("/api/admin/upload-video", adminUploadVideoHandler)
	secureHandle("/api/profile/avatar", apiAvatarUploadHandler)
	secureHandle("/api/profile/background", apiBackgroundUploadHandler)
	secureHandle("/api/profile/avatar-frame", apiAvatarFrameHandler)
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
	secureHandle("/api/users/search", apiUsersSearchGet)
	secureHandle("/api/favorites/anime", apiFavoriteAnimeToggle)
	secureHandle("/api/favorites/episode", apiFavoriteEpisodeToggle)

	log.Println("Сервер Ancen запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
