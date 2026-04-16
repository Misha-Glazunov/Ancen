package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"github.com/gorilla/websocket"
	"sync"
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
	// Данные для страницы аниме (временная заглушка)
	data := struct {
		Title       string
		Poster      string
		Description string
		Episodes    []struct{ ID, Num int }
	}{
		Title:       "Наруто",
		Poster:      "https://via.placeholder.com/200",
		Description: "История о ниндзя, который мечтает стать Хокаге.",
		Episodes:    []struct{ ID, Num int }{{1, 1}, {2, 2}},
	}
	err := templates.ExecuteTemplate(w, "anime.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func watchHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	episodeID := r.URL.Query().Get("episode")
	data := struct{ EpisodeNum string }{EpisodeNum: episodeID}
	err := templates.ExecuteTemplate(w, "watch.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Пока заглушка — позже будем получать имя пользователя из сессии
	data := struct{ Username string }{Username: "Гость"}
	err := templates.ExecuteTemplate(w, "profile.html", data)
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
    
    // Только POST
    if r.Method != http.MethodPost {
        http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
        return
    }
    
    // Проверка авторизации
    userID, err := getUserIDFromSession(r)
    if err != nil {
        http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
        return
    }
    
    // Парсим JSON
    var req struct {
        EpisodeID    int    `json:"episode_id"`
        TimestampSec int    `json:"timestamp_sec"`
        EmotionType  string `json:"emotion_type"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
        return
    }
    
    // Валидация
    if req.EpisodeID == 0 || req.TimestampSec < 0 || req.EmotionType == "" {
        http.Error(w, `{"error":"Missing fields"}`, http.StatusBadRequest)
        return
    }
    
    // Вставляем в БД
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

// ---------- Запуск сервера ----------
func main() {
	// Подключение к MySQL
	var err error
	// Формат: "пользователь:пароль@tcp(хост:порт)/имя_бд?charset=utf8mb4&parseTime=true"
	dsn := "ancen_user:ancen123@tcp(localhost:3306)/ancen?charset=utf8mb4&parseTime=true"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Ошибка подключения к БД:", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatal("БД не отвечает:", err)
	}
	log.Println("Подключено к MySQL")

	store = sessions.NewCookieStore([]byte("fdjeoifwjf"))
	
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

	log.Println("Сервер Ancen запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}