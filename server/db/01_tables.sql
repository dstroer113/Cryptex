-- ============================================
-- Cryptex Database Schema (PostgreSQL 15+)
-- Приоритет: БЕЗОПАСНОСТЬ
-- Файл: 01_tables.sql
-- ============================================

-- Расширения
CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- для bcrypt, gen_random_bytes

-- ============================================
-- 1. Таблица пользователей
-- Пароль: bcrypt (60 символов)
-- Соль хранится внутри bcrypt-хеша
-- ============================================
CREATE TABLE users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(50)  UNIQUE NOT NULL,
    password_hash   VARCHAR(100) NOT NULL,       -- bcrypt: $2a$... (60 chars + запас)
    email           VARCHAR(254) UNIQUE NOT NULL, -- RFC 5321
    public_key      TEXT         NOT NULL,        -- RSA-4096 public key PEM
    is_active       BOOLEAN      DEFAULT TRUE,
    failed_attempts INT          DEFAULT 0,       -- rate-limiting на уровне БД
    locked_until    TIMESTAMPTZ,                  -- временная блокировка
    created_at      TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- 2. Таблица сессийш
-- Токен: 64 hex символа (256 бит случайности)
-- ============================================
CREATE TABLE sessions (
    id              SERIAL PRIMARY KEY,
    user_id         INT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token           VARCHAR(64)  UNIQUE NOT NULL,
    ip_address      INET,
    expires_at      TIMESTAMPTZ  NOT NULL,
    created_at      TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP,
    is_revoked      BOOLEAN      DEFAULT FALSE
);

-- ============================================
-- 3. Таблица контактов
-- Связь user_a → user_b (уже подтверждённая)
-- ============================================
CREATE TABLE contacts (
    id              SERIAL PRIMARY KEY,
    user_id_a       INT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_id_b       INT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id_a, user_id_b),
    CHECK(user_id_a <> user_id_b)
);

-- ============================================
-- 4. Таблица запросов в контакты
-- sender: отправитель запроса
-- receiver: получатель (должен принять)
-- comment: комментарий от отправителя
-- ============================================
CREATE TABLE contact_requests (
    id              SERIAL PRIMARY KEY,
    sender_id       INT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receiver_id     INT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    comment         VARCHAR(500) DEFAULT '',
    status          VARCHAR(20)  NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'accepted', 'rejected')),
    created_at      TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP,
    responded_at    TIMESTAMPTZ,
    UNIQUE(sender_id, receiver_id, status)  -- только один активный запрос
);

-- ============================================
-- 5. Таблица метаданных файловых передач
-- sender_id / receiver_id — кто кому отправляет
-- file_name — исходное имя файла
-- file_hash — SHA-256 от ЗАШИФРОВАННОГО файла (проверка целостности)
-- storage_path — относительный путь на сервере
-- ============================================
CREATE TABLE file_transfers (
    id                  SERIAL PRIMARY KEY,
    sender_id           INT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receiver_id         INT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_name           VARCHAR(255) NOT NULL,
    file_hash           VARCHAR(64)  NOT NULL,  -- SHA-256 hex
    file_size           BIGINT       NOT NULL CHECK (file_size > 0 AND file_size <= 31457280), -- 30 MB
    storage_path        VARCHAR(512) NOT NULL,  -- путь на серверном диске
    encryption_iv       VARCHAR(64),            -- IV для проверки сервером (не ключ!)
    status              VARCHAR(20)  NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'uploading', 'ready', 'downloading', 'completed', 'cancelled', 'expired')),
    bytes_transferred   BIGINT       DEFAULT 0,
    created_at          TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP,
    completed_at        TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ  NOT NULL,   -- авто-удаление
    max_downloads       INT          DEFAULT 3,   -- защита от перебора
    download_count      INT          DEFAULT 0
);

-- ============================================
-- 6. Таблица журнала аудита
-- Все операции логируются
-- ============================================
CREATE TABLE audit_logs (
    id              SERIAL PRIMARY KEY,
    user_id         INT          REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(100) NOT NULL,
    table_name      VARCHAR(50),
    record_id       INT,
    details         JSONB,
    ip_address      INET,
    success         BOOLEAN      NOT NULL,
    created_at      TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- Индексы
-- ============================================
CREATE INDEX idx_users_username       ON users(username);
CREATE INDEX idx_users_email          ON users(email);
CREATE INDEX idx_sessions_token       ON sessions(token);
CREATE INDEX idx_sessions_user        ON sessions(user_id);
CREATE INDEX idx_sessions_expires     ON sessions(expires_at);
CREATE INDEX idx_contacts_user_a      ON contacts(user_id_a);
CREATE INDEX idx_contacts_user_b      ON contacts(user_id_b);
CREATE INDEX idx_contact_requests_receiver ON contact_requests(receiver_id, status);
CREATE INDEX idx_contact_requests_sender   ON contact_requests(sender_id);
CREATE INDEX idx_file_transfers_sender    ON file_transfers(sender_id);
CREATE INDEX idx_file_transfers_receiver  ON file_transfers(receiver_id);
CREATE INDEX idx_file_transfers_status    ON file_transfers(status);
CREATE INDEX idx_file_transfers_expires   ON file_transfers(expires_at);
CREATE INDEX idx_audit_logs_user      ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_time      ON audit_logs(created_at);

-- ============================================
-- Ограничение: не более 50 MB зашифрованных файлов на пользователя
-- ============================================
CREATE OR REPLACE FUNCTION check_user_storage_quota()
RETURNS TRIGGER AS $$
DECLARE
    total BIGINT;
BEGIN
    SELECT COALESCE(SUM(file_size), 0) INTO total
    FROM file_transfers
    WHERE sender_id = NEW.sender_id
      AND status IN ('ready', 'downloading');

    IF total + NEW.file_size > 52428800 THEN  -- 50 MB
        RAISE EXCEPTION 'Storage quota exceeded for user %', NEW.sender_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_check_storage_quota
    BEFORE INSERT ON file_transfers
    FOR EACH ROW
    EXECUTE FUNCTION check_user_storage_quota();