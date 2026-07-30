-- Восстановлено по коду cmd/server/*.go, т.к. оригинальной схемы/дампа в репозитории нет

CREATE TABLE IF NOT EXISTS users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    is_admin        TINYINT(1) NOT NULL DEFAULT 0,
    email           VARCHAR(500) NOT NULL DEFAULT '',
    email_confirmed TINYINT(1) NOT NULL DEFAULT 0,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS anime (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    title       VARCHAR(255) NOT NULL,
    description TEXT,
    poster_url  VARCHAR(500) DEFAULT '',
    genres      VARCHAR(255) DEFAULT '',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS episodes (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    anime_id        INT NOT NULL,
    episode_num     INT NOT NULL,
    title           VARCHAR(255) NOT NULL DEFAULT '',
    video_url       VARCHAR(500) NOT NULL DEFAULT '',
    intro_start_sec INT DEFAULT NULL,
    intro_end_sec   INT DEFAULT NULL,
    outro_start_sec INT DEFAULT NULL,
    outro_end_sec   INT DEFAULT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_anime_episode (anime_id, episode_num),
    FOREIGN KEY (anime_id) REFERENCES anime(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS emotions (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    user_id        INT NOT NULL,
    episode_id     INT NOT NULL,
    timestamp_sec  INT NOT NULL,
    emotion_type   VARCHAR(16) NOT NULL,
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_emotions_episode (episode_id),
    KEY idx_emotions_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (episode_id) REFERENCES episodes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS comments (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    user_id        INT NOT NULL,
    episode_id     INT NOT NULL,
    timestamp_sec  INT NOT NULL DEFAULT 0,
    text           VARCHAR(500) NOT NULL,
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_comments_episode (episode_id),
    KEY idx_comments_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (episode_id) REFERENCES episodes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
