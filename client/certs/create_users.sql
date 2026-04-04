-- SQL скрипт для создания таблицы пользователей в PostgreSQL
-- Выполните этот скрипт в pgAdmin или через psql

-- Подключение к базе данных postgres
\c postgres

-- Создание таблицы users (если ещё не создана)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(64) NOT NULL,
    salt VARCHAR(32) NOT NULL,
    email VARCHAR(100),
    public_key TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Создание функции для хеширования пароля
CREATE OR REPLACE FUNCTION create_user_with_hash(
    p_username VARCHAR(50),
    p_password VARCHAR(100),
    p_email VARCHAR(100) DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
    v_salt TEXT;
    v_hash TEXT;
BEGIN
    -- Генерация случайной соли (16 байт в hex = 32 символа)
    v_salt := encode(gen_random_bytes(16), 'hex');
    
    -- Вычисление хеша: SHA256(password + salt)
    v_hash := encode(digest(p_password || v_salt, 'sha256'), 'hex');
    
    -- Вставка пользователя
    INSERT INTO users (username, password_hash, salt, email)
    VALUES (p_username, v_hash, v_salt, p_email)
    ON CONFLICT (username) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- Создание тестового пользователя 'testuser' с паролем 'test123'
SELECT create_user_with_hash('testuser', 'test123', 'test@cryptex.local');

-- Создание пользователя 'admin' с паролем 'admin123'
SELECT create_user_with_hash('admin', 'admin123', 'admin@cryptex.local');

-- Проверка созданных пользователей
SELECT id, username, email, is_active, created_at FROM users;

-- Для проверки хеша конкретного пользователя:
-- SELECT username, password_hash, salt FROM users WHERE username = 'testuser';
