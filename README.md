# 🔐 Cryptex — безопасный обмен файлами через сервер-ретранслятор (v2.0 beta)

**Cryptex** — клиент-серверное приложение для безопасной передачи файлов между пользователями через сервер-ретранслятор. Файлы **не хранятся** на диске сервера — данные живут только в оперативной памяти на время передачи.

## Архитектура

```
┌───────────┐     TLS 1.2+      ┌─────────────────┐     TLS 1.2+      ┌───────────┐
│ Отправитель│ ────────────────→ │  Cryptex Server  │ ────────────────→ │ Получатель │
│ (клиент)   │ ←──────────────── │  (RAM-only relay)│ ←──────────────── │ (клиент)   │
└───────────┘                   └────────┬────────┘                   └───────────┘
                                         │
                                    PostgreSQL
                                  (пользователи, контакты,
                                   сессии, аудит)
```

- **Файлы не пишутся на диск сервера** — только в ОЗУ, после скачивания удаляются
- **TLS 1.2+** между клиентом и сервером
- **AES-256-GCM** для локального шифрования (журнал операций)
- **Bcrypt** для хеширования паролей (сервер)
- **SHA-256** для контроля целостности файлов
- **HMAC-SHA256** для аутентификации пакетов
- **Rate limiting** — 120 запросов/мин на клиента

## Возможности

| Функция | Статус |
|---|---|
| Регистрация / авторизация (bcrypt, токены) | ✅ |
| Управление контактами (добавить / принять / отклонить) | ✅ |
| Отправка файлов до 30 МБ через сервер-ретранслятор | ✅ |
| Приём файлов с выбором места сохранения | ✅ |
| История отправленных / принятых файлов | ✅ |
| Журнал операций (зашифрован AES-256-GCM) | ✅ |
| Офлайн-режим (локальное шифрование без сервера) | ✅ |
| Консольное управление сервером (статус, БД, аудит) | ✅ |
| Настройки подключения (IP, порт, SSL-сертификат) | ✅ |
| Лог-файл с ротацией на сервере | ✅ |

## Сборка из исходников

### Зависимости

| Компонент | Версия | Примечание |
|---|---|---|
| Qt | 6.5+ | Модули: Core, Network, Sql, Widgets |
| OpenSSL | 3.x | libcrypto, libssl |
| PostgreSQL | 15+ | Только для сервера |
| Компилятор | MSVC 2022 / GCC 11+ / Clang 15+ | C++17 |
| CMake / QMake | | Сборка |
| MSYS2 (Windows) | | Для OpenSSL и инструментов |

### Сборка клиента (Windows, MSYS2 UCRT64)

```bash
# 1. Установить Qt 6 и MSYS2
# 2. В MSYS2 UCRT64:
pacman -S mingw-w64-ucrt-x86_64-qt6-base mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-cmake

# 3. Отредактировать client/client.pro — путь к OpenSSL
INCLUDEPATH += F:/msys64/ucrt64/include
LIBS += -LF:/msys64/ucrt64/lib -lcrypto -lssl

# 4. Собрать
cd client
qmake6 client.pro
make -j$(nproc)
```

### Сборка сервера (Windows, MSYS2 UCRT64)

```bash
cd server
qmake6 server.pro
make -j$(nproc)
```

### Сборка клиента (Linux)

```bash
sudo apt install qt6-base-dev libssl-dev cmake g++ -y
cd client
qmake6 client.pro
make -j$(nproc)
```

### Сборка сервера (Linux)

```bash
sudo apt install qt6-base-dev libssl-dev libpq-dev postgresql-16 cmake g++ -y
cd server
qmake6 server.pro  # предварительно убрать/заменить пути MSYS2 из server.pro
make -j$(nproc)
```

## Развёртывание сервера на VPS

### 1. Требования к VPS

- **ОС:** Ubuntu 22.04/24.04
- **ОЗУ:** 1-2 ГБ (файлы до 30 МБ хранятся в ОЗУ на время передачи)
- **Диск:** 10+ ГБ (только БД и бинарник)
- **Порты:** 8443 (TLS сервер) + 5432 (PostgreSQL, localhost only)

### 2. Установка зависимостей

```bash
apt update
apt install -y postgresql-16 qt6-base-dev libssl-dev libgl1-mesa-dev cmake g++ make
```

### 3. Настройка PostgreSQL

```bash
sudo -u postgres psql <<SQL
CREATE DATABASE cryptex;
CREATE USER cryptex WITH PASSWORD 'ваш_пароль';
GRANT ALL ON DATABASE cryptex TO cryptex;
\c cryptex
\i /opt/cryptex/server/db/01_tables.sql
\i /opt/cryptex/server/db/02_procedures.sql
\i /opt/cryptex/server/db/03_triggers.sql
SQL
```

### 4. Сборка сервера

```bash
cd server
# Заменить INCLUDEPATH/LIBS MSYS2 в server.pro на системные:
#   LIBS += -lssl -lcrypto
qmake6 server.pro
make -j$(nproc)
```

### 5. Конфигурация

```bash
mkdir -p /opt/cryptex /etc/cryptex/certs /var/log/cryptex
cp server /opt/cryptex/
cp server.conf.example /opt/cryptex/server.conf
nano /opt/cryptex/server.conf
```

Пример `/opt/cryptex/server.conf`:
```ini
[Database]
host=localhost
port=5432
name=cryptex
user=cryptex
password=ваш_пароль

[Server]
listen_ip=0.0.0.0
listen_port=8443
ssl_cert=/etc/cryptex/certs/server.crt
ssl_key=/etc/cryptex/certs/server.key

[Logging]
file=/var/log/cryptex/server.log
max_size_mb=10
max_files=5
```

### 6. Генерация SSL-сертификатов

```bash
# Самоподписанный (для теста):
openssl req -x509 -newkey rsa:4096 -keyout /etc/cryptex/certs/server.key \
  -out /etc/cryptex/certs/server.crt -days 365 -nodes -subj "/CN=ваш_домен"

# Или Let's Encrypt + Nginx reverse proxy:
certbot certonly --standalone -d ваш_домен.ru
# Затем nginx проксирует :443 → :8443
```

### 7. Systemd-сервис

```bash
cat > /etc/systemd/system/cryptex.service <<EOF
[Unit]
Description=Cryptex Server
After=network.target postgresql.service

[Service]
Type=simple
User=cryptex
WorkingDirectory=/opt/cryptex
ExecStart=/opt/cryptex/server --config /opt/cryptex/server.conf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now cryptex
systemctl status cryptex
```

### 8. Файрвол

```bash
# Открываем только порт сервера (PostgreSQL слушает localhost)
ufw allow 8443/tcp
ufw enable
```

### 9. Управление сервером

Подключитесь по SSH, запустите сервер в интерактивном режиме или смотрите логи:

```bash
# Интерактивная консоль (команды: 1-5, h, 0)
/opt/cryptex/server --config /opt/cryptex/server.conf

# Просмотр логов
tail -f /var/log/cryptex/server.log
```

**Команды консоли сервера:**

| Клавиша | Действие |
|---|---|
| `1` | Статус сервера (адрес, БД, потоки, лог-файл) |
| `2` | Активные соединения (потоки, TLS, rate limit) |
| `3` | Статистика БД (пользователи, контакты, сессии) |
| `4` | Файлы в ОЗУ (жизненный цикл ретранслятора) |
| `5` | Лог аудита БД (последние 20 записей) |
| `h` | Справка |
| `0` | Выход |

## Использование клиента

### Первый запуск

1. **Регистрация** — логин (3-50 символов), пароль (мин. 8), email
2. **Вход** — логин + пароль
3. **Добавление контакта** — вкладка "Контакты" → ввести имя пользователя → "Добавить"

### Отправка файла

1. Вкладка **"Передача файлов"**
2. Выбрать контакт из списка (проверить онлайн-статус: 🟢/🔴)
3. Нажать "Обзор" → выбрать файл (до 30 МБ)
4. Нажать "Отправить" → файл шифруется и отправляется на сервер
5. Получатель увидит файл в "Ожидают получения"

### Получение файла

1. Вкладка **"Передача файлов"** → секция "Ожидают получения"
2. Выделить строку с файлом → нажать "Скачать"
3. Выбрать место сохранения → файл загружается
4. После завершения → запись появляется в "Принятые"

### Журнал операций

Вкладка **"Журнал"** — все операции зашифрованы AES-256-GCM, хранятся локально.

### Настройки

Меню → **"Настройки"** → вкладки:
- **Подключение** — адрес сервера, порт, SSL-сертификат
- **Безопасность** — смена пароля, экспорт ключей, очистка данных
- **О программе** — версия, технологии

## Безопасность

| Уровень | Механизм |
|---|---|
| Канал | TLS 1.2+ (клиент ↔ сервер) |
| Пакеты | AES-256-CBC + HMAC-SHA256 (сессионные ключи) |
| Пароли | Bcrypt (cost=12) через pgcrypto |
| Файлы | SHA-256 контроль целостности |
| Локально | AES-256-GCM (журнал операций) |
| Аудит | PostgreSQL audit_log + rate limiting |

## Лицензия

MIT License

## Автор

Cryptex v2.0 — проект с открытым исходным кодом.