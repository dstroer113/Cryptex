-- ============================================
-- Триггер: Автоматическое обновление updated_at
-- ============================================
CREATE OR REPLACE FUNCTION trg_update_timestamp_func()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_users_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION trg_update_timestamp_func();

-- ============================================
-- Триггер: Аудит при вставке пользователя
-- ============================================
CREATE OR REPLACE FUNCTION trg_audit_user_insert_func()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values)
    VALUES (NEW.id, 'INSERT', 'users', NEW.id,
            jsonb_build_object('username', NEW.username, 'email', NEW.email));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_user_insert
    AFTER INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION trg_audit_user_insert_func();

-- ============================================
-- Триггер: Аудит при создании передачи
-- ============================================
CREATE OR REPLACE FUNCTION trg_log_transfer_insert_func()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values)
    VALUES (NEW.sender_id, 'TRANSFER_CREATED', 'transfer_logs', NEW.id,
            jsonb_build_object('file_id', NEW.file_id, 'status', NEW.status));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_log_transfer_insert
    AFTER INSERT ON transfer_logs
    FOR EACH ROW
    EXECUTE FUNCTION trg_log_transfer_insert_func();
