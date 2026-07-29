package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

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

func getUserIDFromSession(r *http.Request) (int, error) {
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

// currentUsername возвращает имя пользователя из сессии, либо "" для гостя.
// Используется шаблоном header.html, чтобы показать гостевую (Header_Unlogin)
// или авторизованную шапку.
func currentUsername(r *http.Request) string {
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
func checkAndUnlockAchievements(userID int) {
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
	}

	for _, c := range checks {
		if c.check() {
			unlockAchievement(userID, c.id)
		}
	}
}

// unlockAchievement разблокирует ачивку, если ещё не разблокирована
func unlockAchievement(userID int, achievementID string) {
	_, err := db.Exec(`
		INSERT IGNORE INTO user_achievements (user_id, achievement_id)
		VALUES (?, ?)
	`, userID, achievementID)
	if err != nil {
		log.Printf("unlockAchievement error: %v", err)
	}
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
	// Таймкоды автоскипа опенинга/эндинга (NULL = не задано, кнопка на плеере не показывается)
	for _, col := range []string{"intro_start_sec", "intro_end_sec", "outro_start_sec", "outro_end_sec"} {
		if _, err := db.Exec("ALTER TABLE episodes ADD COLUMN " + col + " INT DEFAULT NULL"); err != nil {
			log.Printf("ALTER TABLE episodes (%s) может уже существовать: %v", col, err)
		}
	}
}

// ---------- Обработчики ----------

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Отдаём реальный контент главной страницы сразу по "/" (важно для SEO —
	// поисковый робот должен видеть контент без JS-редиректа). Прелоадер
	// показывается как визуальный оверлей внутри home.html и просто гаснет,
	// без навигации на отдельный URL.
	render(w, "home.html", PageData{
		Title:    "AniMemory — смотри аниме и делись эмоциями в реальном времени",
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
		err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", username).Scan(&userID, &dbPassword)
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

		resetLoginAttempts(username, ip)

		session, _ := store.Get(r, "ancen-session")
		session.Values["user_id"] = userID
		session.Values["username"] = username
		session.Options = &sessions.Options{
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
			SameSite: http.SameSiteLaxMode,
			MaxAge:   86400 * 7,
		}
		err = session.Save(r, w)
		if err != nil {
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
		username := r.FormValue("username")
		password := r.FormValue("password")
		email := r.FormValue("email")

		if username == "" || password == "" {
			render(w, "register.html", PageData{Title: "Регистрация", Error: "Заполните все поля"})
			return
		}

		if len(password) < 6 {
			render(w, "register.html", PageData{Title: "Регистрация", Error: "Пароль должен быть не менее 6 символов"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			render(w, "register.html", PageData{Title: "Регистрация", Error: "Ошибка хеширования пароля"})
			return
		}

		var result sql.Result
		if email != "" {
			result, err = db.Exec("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", username, email, string(hashedPassword))
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
	}
	err = db.QueryRow("SELECT id, title, description, poster_url, genres FROM anime WHERE id = ?", id).Scan(
		&anime.ID, &anime.Title, &anime.Description, &anime.Poster, &anime.Genres)
	if err != nil {
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	rows, err := db.Query("SELECT id, episode_num, title FROM episodes WHERE anime_id = ? ORDER BY episode_num", id)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Episode struct {
		ID    int
		Num   int
		Title string
	}
	episodes := []Episode{}
	for rows.Next() {
		var ep Episode
		if err := rows.Scan(&ep.ID, &ep.Num, &ep.Title); err != nil {
			continue
		}
		episodes = append(episodes, ep)
	}

	data := struct {
		Anime    interface{}
		Episodes []Episode
		Username string
	}{Anime: anime, Episodes: episodes, Username: currentUsername(r)}

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
		Title      string
		VideoURL   string
		IntroStart sql.NullInt64
		IntroEnd   sql.NullInt64
		OutroStart sql.NullInt64
		OutroEnd   sql.NullInt64
	}
	err = db.QueryRow(`SELECT id, anime_id, episode_num, title, video_url,
		intro_start_sec, intro_end_sec, outro_start_sec, outro_end_sec
		FROM episodes WHERE id = ?`, episodeID).Scan(
		&episode.ID, &episode.AnimeID, &episode.EpisodeNum, &episode.Title, &episode.VideoURL,
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

	data := struct {
		EpisodeNum int
		VideoURL   string
		Title      string
		UserLevel  UserLevelInfo
		Username   string
		// IntroStart/IntroEnd/OutroStart/OutroEnd: 0 здесь означает "не задано" (NULL в БД),
		// а не "начинается с 0-й секунды" — фронтенду нужно отдельно проверять,
		// заданы ли таймкоды (например, через ненулевой IntroEnd), прежде чем показывать кнопку "Пропустить".
		IntroStart int64
		IntroEnd   int64
		OutroStart int64
		OutroEnd   int64
	}{
		EpisodeNum: episode.EpisodeNum,
		VideoURL:   episode.VideoURL,
		Title:      episode.Title,
		UserLevel:  levelInfo,
		Username:   currentUsername(r),
		IntroStart: episode.IntroStart.Int64,
		IntroEnd:   episode.IntroEnd.Int64,
		OutroStart: episode.OutroStart.Int64,
		OutroEnd:   episode.OutroEnd.Int64,
	}

	err = templates.ExecuteTemplate(w, "watch.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	userID, err := getUserIDFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var username string
	err = db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
	if err != nil {
		username = "Гость"
	}

	// Получаем XP и уровень
	var xp int
	db.QueryRow("SELECT xp FROM user_xp WHERE user_id = ?", userID).Scan(&xp)
	levelInfo := getLevelInfo(xp)

	// Получаем ачивки
	userAchievements := getUserAchievements(userID)

	// Получаем статистику
	var emotionCount, commentCount, episodeCount int
	db.QueryRow("SELECT COUNT(*) FROM emotions WHERE user_id = ?", userID).Scan(&emotionCount)
	db.QueryRow("SELECT COUNT(*) FROM comments WHERE user_id = ?", userID).Scan(&commentCount)
	db.QueryRow("SELECT COUNT(DISTINCT episode_id) FROM emotions WHERE user_id = ?", userID).Scan(&episodeCount)

	data := struct {
		Username     string
		Level        UserLevelInfo
		Achievements []UserAchievement
		EmotionCount int
		CommentCount int
		EpisodeCount int
	}{
		Username:     username,
		Level:        levelInfo,
		Achievements: userAchievements,
		EmotionCount: emotionCount,
		CommentCount: commentCount,
		EpisodeCount: episodeCount,
	}

	err = templates.ExecuteTemplate(w, "profile.html", data)
	if err != nil {
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
	validEmotions := map[string]bool{
		"😭": true, "🔥": true, "🤯": true, "🥰": true, "💢": true,
	}
	if !validEmotions[req.EmotionType] {
		http.Error(w, `{"error":"Invalid emotion type"}`, http.StatusBadRequest)
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
	checkAndUnlockAchievements(userID)

	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, `{"status":"ok"}`)
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

	rows, err := db.Query(`
		SELECT e.emotion_type, e.timestamp_sec, u.username
		FROM emotions e
		JOIN users u ON e.user_id = u.id
		WHERE e.episode_id = ?
		ORDER BY e.created_at DESC
		LIMIT ? OFFSET ?
	`, episodeID, pageSize, offset)
	if err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Emotion struct {
		EmotionType  string `json:"emotion_type"`
		TimestampSec int    `json:"timestamp_sec"`
		Username     string `json:"username"`
	}
	emotions := []Emotion{}
	for rows.Next() {
		var e Emotion
		if err := rows.Scan(&e.EmotionType, &e.TimestampSec, &e.Username); err != nil {
			continue
		}
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

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
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

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	// Разрешаем апгрейд только с того же хоста, что и сам сервер (защита от
	// Cross-Site WebSocket Hijacking: без этой проверки чужой сайт мог бы
	// открыть WS-соединение от имени залогиненного пользователя, используя
	// его cookie, которую браузер прикрепляет автоматически).
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// Запрос не от браузера (нет Origin) — например, curl/wscat при разработке
			return true
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return u.Host == r.Host
	},
}

// Сообщение от клиента
type WsMessage struct {
	Type         string `json:"type"`
	EpisodeID    int    `json:"episode_id"`
	TimestampSec int    `json:"timestamp_sec"`
	EmotionType  string `json:"emotion_type"`
	Username     string `json:"username"`
}

// Клиент
type Client struct {
	conn      *websocket.Conn
	send      chan []byte
	episodeID int
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

			data, _ := json.Marshal(msg)
			for client := range clients {
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
	session, err := store.Get(r, "ancen-session")
	if err != nil {
		log.Println("Session get error:", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	userID, ok := session.Values["user_id"].(int)
	if !ok || userID == 0 {
		log.Println("user_id not found")
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
	client := &Client{
		conn:      conn,
		send:      make(chan []byte, 256),
		episodeID: episodeID,
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
			log.Printf("📨 Received WS message: %+v", msg)
			if msg.Type == "emotion" && msg.EpisodeID == episodeID {
				_, err = db.Exec("INSERT INTO emotions (user_id, episode_id, timestamp_sec, emotion_type) VALUES (?, ?, ?, ?)",
					userID, msg.EpisodeID, msg.TimestampSec, msg.EmotionType)
				if err != nil {
					log.Println("DB error:", err)
					continue
				}
				msg.Username = username
				hub.broadcast <- msg

				// Начисляем XP за эмоцию через WebSocket (с учётом анти-фарм лимита на эпизод)
				awardEmotionXP(userID, msg.EpisodeID)
				checkAndUnlockAchievements(userID)
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
	checkAndUnlockAchievements(userID)

	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, `{"status":"ok"}`)
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

	rows, err := db.Query(`
		SELECT c.id, u.username, c.timestamp_sec, c.text, c.created_at
		FROM comments c
		JOIN users u ON c.user_id = u.id
		WHERE c.episode_id = ?
		ORDER BY c.created_at DESC
		LIMIT ? OFFSET ?
	`, episodeID, pageSize, offset)
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

	pageStr := r.URL.Query().Get("page")
	pageSizeStr := r.URL.Query().Get("pageSize")

	page := 1
	if pageStr != "" {
		p, err := strconv.Atoi(pageStr)
		if err == nil && p > 0 {
			page = p
		}
	}

	pageSize := 25
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
	var results []Anime

	if query != "" {
		rows, err := db.Query(`
			SELECT id, title, description, poster_url, genres
			FROM anime
			WHERE title LIKE ? OR description LIKE ? OR genres LIKE ?
			ORDER BY title
			LIMIT ? OFFSET ?
		`, "%"+query+"%", "%"+query+"%", "%"+query+"%", pageSize, offset)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var a Anime
			if err := rows.Scan(&a.ID, &a.Title, &a.Description, &a.Poster, &a.Genres); err != nil {
				continue
			}
			results = append(results, a)
		}
	}

	data := struct {
		Query    string
		Results  []Anime
		Username string
	}{Query: query, Results: results, Username: currentUsername(r)}
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

// adminUploadVideoHandler принимает сырой видеофайл, транскодирует его в adaptive
// HLS (ffmpeg) и заливает в MinIO. Защищено статическим токеном из ADMIN_UPLOAD_TOKEN —
// временно, до появления настоящей админки с ролями (см. 13_Дальнейшие_улучшения).
func adminUploadVideoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if r.FormValue("token") != os.Getenv("ADMIN_UPLOAD_TOKEN") || os.Getenv("ADMIN_UPLOAD_TOKEN") == "" {
		http.Error(w, `{"error":"Forbidden"}`, http.StatusForbidden)
		return
	}

	animeID, err1 := strconv.Atoi(r.FormValue("anime_id"))
	episodeNum, err2 := strconv.Atoi(r.FormValue("episode_num"))
	title := r.FormValue("title")
	if err1 != nil || err2 != nil || title == "" {
		http.Error(w, `{"error":"anime_id, episode_num и title обязательны"}`, http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("video")
	if err != nil {
		http.Error(w, `{"error":"Файл видео (поле video) обязателен"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

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
	session, _ := store.Get(r, "ancen-session")
	session.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
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

// forgotPasswordHandler — GET/POST /forgot-password
func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		if email == "" {
			render(w, "forgot-password.html", PageData{Title: "Восстановление пароля", Error: "Введите email"})
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
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
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

	initMinioClient()

	go hub.run()

	// Регистрация маршрутов
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/anime/", animeHandler)
	http.HandleFunc("/watch", watchHandler)
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/api/emotion", apiEmotionPost)
	http.HandleFunc("/api/emotions", apiEmotionsGet)
	http.HandleFunc("/ws", wsHandler)
	http.HandleFunc("/api/emotions/stats", apiEmotionsStats)
	http.HandleFunc("/api/comment", apiCommentPost)
	http.HandleFunc("/api/comments", apiCommentsGet)
	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/forgot-password", forgotPasswordHandler)
	http.HandleFunc("/new-password", newPasswordHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/robots.txt", robotsHandler)
	http.HandleFunc("/sitemap.xml", sitemapHandler)
	http.HandleFunc("/api/progress", func(w http.ResponseWriter, r *http.Request) {
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
	http.HandleFunc("/api/achievements", apiAchievementsGet)
	http.HandleFunc("/api/level", apiLevelGet)
	http.HandleFunc("/api/achievements/all", apiAllAchievementsGet)
	http.HandleFunc("/api/admin/upload-video", adminUploadVideoHandler)
	http.HandleFunc("/api/change-password", apiChangePasswordHandler)

	log.Println("Сервер Ancen запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}