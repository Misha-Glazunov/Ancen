package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"sync"

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



// PageData используется для передачи данных в шаблоны (например, для ошибок/успеха)
type PageData struct {
	Title   string
	Error   string
	Success string
	// для других страниц можно добавлять поля
}

// Инициализация: загружаем все шаблоны из папки web/templates
func init() {
	templates = template.Must(template.ParseGlob("web/templates/*.html"))
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

// ---------- Обработчики ----------

func homeHandler(w http.ResponseWriter, r *http.Request) {
	render(w, "home.html", PageData{Title: "Ancen - Главная"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")

        var userID int
        var dbPassword string
        err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", username).Scan(&userID, &dbPassword)
        if err != nil {
            if err == sql.ErrNoRows {
                log.Println("Login failed: user not found", username)
                render(w, "login.html", PageData{Title: "Вход", Error: "Неверный логин или пароль"})
            } else {
                log.Println("DB error:", err)
                render(w, "login.html", PageData{Title: "Вход", Error: "Ошибка БД"})
            }
            return
        }

        // Сравнение bcrypt
        err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
        if err != nil {
            log.Println("Login failed: wrong password for", username)
            render(w, "login.html", PageData{Title: "Вход", Error: "Неверный логин или пароль"})
            return
        }

        // Сессия
        session, _ := store.Get(r, "ancen-session")
        session.Values["user_id"] = userID
        session.Values["username"] = username
        session.Options = &sessions.Options{
            Path:     "/",
            HttpOnly: true,
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

        if username == "" || password == "" {
            render(w, "register.html", PageData{Title: "Регистрация", Error: "Заполните все поля"})
            return
        }

        // Хешируем пароль
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        if err != nil {
            render(w, "register.html", PageData{Title: "Регистрация", Error: "Ошибка хеширования пароля"})
            return
        }

        _, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, string(hashedPassword))
        if err != nil {
            if strings.Contains(err.Error(), "Duplicate entry") {
                render(w, "register.html", PageData{Title: "Регистрация", Error: "Пользователь уже существует"})
            } else {
                render(w, "register.html", PageData{Title: "Регистрация", Error: "Ошибка БД: " + err.Error()})
            }
            return
        }
        render(w, "register.html", PageData{Title: "Регистрация", Success: "Регистрация успешна! Теперь войдите."})
        return
    }
    render(w, "register.html", PageData{Title: "Регистрация"})
}

func animeHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    // Получаем ID из URL: /anime/1
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

    // Получаем список эпизодов
    rows, err := db.Query("SELECT id, episode_num, title FROM episodes WHERE anime_id = ? ORDER BY episode_num", id)
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    type Episode struct {
        ID  int
        Num int
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
        Anime     interface{}
        Episodes  []Episode
    }{Anime: anime, Episodes: episodes}

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
        ID        int
        AnimeID   int
        EpisodeNum int
        Title     string
        VideoURL  string
    }
    err = db.QueryRow("SELECT id, anime_id, episode_num, title, video_url FROM episodes WHERE id = ?", episodeID).Scan(
        &episode.ID, &episode.AnimeID, &episode.EpisodeNum, &episode.Title, &episode.VideoURL)
    if err != nil {
        if err == sql.ErrNoRows {
            http.NotFound(w, r)
        } else {
            http.Error(w, "Database error", http.StatusInternalServerError)
        }
        return
    }

    data := struct {
        EpisodeNum int
        VideoURL   string
        Title      string
    }{
        EpisodeNum: episode.EpisodeNum,
        VideoURL:   episode.VideoURL,
        Title:      episode.Title,
    }

    err = templates.ExecuteTemplate(w, "watch.html", data)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
    }
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    username := "Гость"
    userID, err := getUserIDFromSession(r)
    if err == nil {
        // Получаем имя пользователя из БД
        err = db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
        if err != nil {
            username = "Гость"
        }
    }
    data := struct{ Username string }{Username: username}
    err = templates.ExecuteTemplate(w, "profile.html", data)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
    }
}

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
    // Белый список эмоций
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
    
    // Запрашиваем последние 50 эмоций с именем пользователя
    rows, err := db.Query(`
        SELECT e.emotion_type, e.timestamp_sec, u.username 
        FROM emotions e
        JOIN users u ON e.user_id = u.id
        WHERE e.episode_id = ?
        ORDER BY e.created_at DESC
        LIMIT 50
    `, episodeID)
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

// WebSocket upgrader
var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { return true }, // для разработки
}

// Сообщение от клиента
type WsMessage struct {
    Type         string `json:"type"`         // "emotion"
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

// Запуск hub (в отдельной горутине)
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
    // Сессия
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

    // episode_id
    episodeIDStr := r.URL.Query().Get("episode_id")
    episodeID, err := strconv.Atoi(episodeIDStr)
    if err != nil || episodeID == 0 {
        http.Error(w, "episode_id required", http.StatusBadRequest)
        return
    }

    // username
    var username string
    err = db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
    if err != nil {
        http.Error(w, "User not found", http.StatusUnauthorized)
        return
    }

    // Upgrade
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

    // Горутина чтения сообщений от клиента
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
            log.Printf("📨 Received WS message: %+v", msg) // ЭТОТ ЛОГ ВАЖЕН
            if msg.Type == "emotion" && msg.EpisodeID == episodeID {
                _, err = db.Exec("INSERT INTO emotions (user_id, episode_id, timestamp_sec, emotion_type) VALUES (?, ?, ?, ?)",
                    userID, msg.EpisodeID, msg.TimestampSec, msg.EmotionType)
                if err != nil {
                    log.Println("DB error:", err)
                    continue
                }
                msg.Username = username
                hub.broadcast <- msg
            }
        }
    }()

    // Горутина отправки сообщений клиенту
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

    // Интервал в секундах (например, 10)
    interval := 10

    // Запрос: группировка по timestamp_sec / interval
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
    _, err = db.Exec("INSERT INTO comments (user_id, episode_id, timestamp_sec, text) VALUES (?, ?, ?, ?)",
        userID, req.EpisodeID, req.TimestampSec, req.Text)
    if err != nil {
        http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
        return
    }
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

    rows, err := db.Query(`
        SELECT c.id, u.username, c.timestamp_sec, c.text, c.created_at
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.episode_id = ?
        ORDER BY c.created_at DESC
        LIMIT 100
    `, episodeID)
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
    if query == "" {
        templates.ExecuteTemplate(w, "search.html", struct{ Query string; Results interface{} }{Query: "", Results: nil})
        return
    }

    // Поиск по таблице anime
    rows, err := db.Query(`
        SELECT id, title, description, poster_url, genres
        FROM anime
        WHERE title LIKE ? OR description LIKE ? OR genres LIKE ?
        ORDER BY title
        LIMIT 25
    `, "%"+query+"%", "%"+query+"%", "%"+query+"%")
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    type Anime struct {
        ID          int
        Title       string
        Description string
        Poster      string
        Genres      string
    }
    results := []Anime{}
    for rows.Next() {
        var a Anime
        if err := rows.Scan(&a.ID, &a.Title, &a.Description, &a.Poster, &a.Genres); err != nil {
            continue
        }
        results = append(results, a)
    }

    data := struct {
        Query   string
        Results []Anime
    }{Query: query, Results: results}
    templates.ExecuteTemplate(w, "search.html", data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "ancen-session")
    session.Options.MaxAge = -1 // удаляем cookie
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

func apiProgressHandler(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodPost:
        apiProgressPost(w, r)
    case http.MethodGet:
        apiProgressGet(w, r)
        
    default:
        http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
    }
}

// ---------- Запуск сервера ----------
func main() {
    godotenv.Load()
    dsn := os.Getenv("DB_USER") + ":" + os.Getenv("DB_PASS") + "@tcp(" + os.Getenv("DB_HOST") + ":" + os.Getenv("DB_PORT") + ")/" + os.Getenv("DB_NAME") + "?charset=utf8mb4&parseTime=true"
    store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	// Подключение к MySQL
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
    http.HandleFunc("/logout", logoutHandler)
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

	log.Println("Сервер Ancen запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}