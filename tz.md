# ТЕХНИЧЕСКОЕ ЗАДАНИЕ
## Сервис аутентификации и авторизации (Auth Service) v2.1
### Микросервисная архитектура, production-ready

> **Версия 2.1** — исправлена по результатам аудита безопасности и архитектурной ревью.  
> Ключевые изменения: устранена критическая уязвимость OAuth callback (токены в URL),
> добавлен MFA/TOTP, скорректированы нереалистичные NFR, добавлен session management,
> проработана ротация RSA-ключей, исправлены ошибки в примерах кода.

---

## Оглавление

1. [Общие положения](#1-общие-положения)
2. [Архитектура системы](#2-архитектура-системы)
3. [Модель данных и ER-диаграмма](#3-модель-данных-и-er-диаграмма)
4. [Компоненты и их ответственность](#4-компоненты-и-их-ответственность)
5. [Аутентификация](#5-аутентификация)
6. [Авторизация (RBAC/HRBAC)](#6-авторизация-rbachrbac)
7. [Токены и безопасность](#7-токены-и-безопасность)
8. [API спецификация (OpenAPI 3.1)](#8-api-спецификация-openapi-31)
9. [Интеграция с API Gateway](#9-интеграция-с-api-gateway)
10. [Безопасность](#10-безопасность)
11. [Нефункциональные требования](#11-нефункциональные-требования)
12. [Критерии готовности](#12-критерии-готовности)
13. [Roadmap и этапы](#13-roadmap-и-этапы)
- [Приложение A: docker-compose](#приложение-a-пример-docker-compose-для-разработки)
- [Приложение B: Метрики](#приложение-b-ключевые-метрики-для-мониторинга)
- [Приложение C: Email-сервис](#приложение-c-email-сервис)
- [Приложение D: Ротация RSA-ключей](#приложение-d-процедура-ротации-rsa-ключей)

---

## 1. Общие положения

### 1.1. Назначение системы

Разработать централизованный, высокодоступный сервис аутентификации и авторизации для микросервисной архитектуры, обеспечивающий:

- Аутентификацию по email/паролю и через OAuth 2.0 / OIDC провайдеров
- Многофакторную аутентификацию (MFA/TOTP) как опциональный и обязательный режим
- Авторизацию на основе RBAC с поддержкой иерархических ролей (HRBAC)
- Управление токенами (JWT access + refresh с ротацией)
- Управление сессиями (просмотр активных устройств, отзыв отдельных сессий)
- Интеграцию с API Gateway (проверка токенов, проброс прав)
- Аудит безопасности (логирование всех критических операций)
- Self-service (смена пароля, восстановление доступа, экспорт данных, удаление аккаунта)

### 1.2. Целевые показатели

> ⚠️ **Важно:** RPS-цели разделены по эндпоинтам. `/auth/login` ограничен скоростью Argon2id
> (~50 RPS на поток) и масштабируется горизонтально, а не вертикально.

| Параметр | Значение | Примечание |
|----------|----------|------------|
| RPS — `/auth/me`, `/auth/refresh` | 5000+ на инстанс | Stateless, кэш Redis |
| RPS — `/auth/login` | 50–100 на инстанс | Ограничен Argon2id; масштабируется репликами |
| RPS — `/auth/register` | 20–50 на инстанс | Ограничен Argon2id |
| Время ответа `/auth/me` (p95) | < 50 мс | С кэшем Redis |
| Время ответа `/auth/login` (p95) | < 500 мс | Включает Argon2id (~300–400 мс) |
| Время ответа `/auth/refresh` (p95) | < 100 мс | |
| Доступность | 99.99% | Кластер из 3+ реплик |
| Время восстановления после сбоя | < 30 секунд | |
| Максимальное количество пользователей | 10 млн+ | |
| Время жизни access token | 15 минут | |
| Время жизни refresh token | 30 дней | |

**Стратегия масштабирования `/auth/login`:**
- Горизонтальное масштабирование: 10 реплик = 500–1000 RPS на логин
- Отдельный `ProcessPoolExecutor` для Argon2 (CPU-bound), изолированный от I/O воркеров
- Async queue для пиковой нагрузки (Redis / RabbitMQ)
### 1.3. Формат ошибок (стандартизированный)

Все ответы с ошибками должны соответствовать единому формату:

```json
{
  "code": 401,
  "message": "Unauthorized",
  "details": {
    "reason": "Invalid or expired access token",
    "field": "Authorization"
  },
  "timestamp": "2026-05-11T10:30:00Z",
  "request_id": "req_abc123def456"
}
```

**HTTP коды ошибок:**

| Код | Описание |
|-----|----------|
| 400 | Bad Request — неверный формат запроса |
| 401 | Unauthorized — нет или невалидный токен |
| 403 | Forbidden — недостаточно прав |
| 404 | Not Found — ресурс не найден |
| 409 | Conflict — email уже существует |
| 422 | Unprocessable Entity — валидация не пройдена |
| 429 | Too Many Requests — превышен лимит |
| 500 | Internal Server Error |
| 503 | Service Unavailable |

---

## 2. Архитектура системы

### 2.1. Общая схема взаимодействия

```
┌─────────┐
│ Client  │
└────┬────┘
     │ HTTPS / TLS 1.3
     ▼
┌──────────────────────────────────────────────────────────┐
│                     API Gateway                          │
│  - Проверка JWT (подпись, срок, blacklist)               │
│  - Проверка permissions (из JWT)                         │
│  - Добавление headers (X-User-Id, X-Roles, X-Perms)     │
│  - Per-service HMAC-подпись внутренних headers           │
│  - Rate limiting (координация с Auth Service via Redis)  │
└────┬──────────────────────────────────────────┬──────────┘
     │                                          │
     │ (запросы без токена или на /auth/*)      │ (внутренние запросы + mTLS)
     ▼                                          ▼
┌─────────────────────────┐          ┌─────────────────────────┐
│    Auth Service         │          │   Business Microservices│
│                         │          │                         │
│ - Регистрация/логин     │◄────────►│ - Проверяют per-service │
│ - OAuth провайдеры      │  (gRPC   │   HMAC подпись headers  │
│ - MFA/TOTP              │   или    │   перед использованием  │
│ - Генерация токенов     │   HTTP   │                         │
│ - Управление ролями     │  + mTLS) │                         │
│ - Session management    │          │                         │
└────┬────────────────────┘          └─────────────────────────┘
     │
     ▼
┌──────────────────────────────────────────────────────────┐
│                    Data Layer                            │
├──────────────┬─────────────────┬─────────────────────────┤
│  PostgreSQL  │  Redis (TLS +   │      Kafka/RabbitMQ     │
│  (основное   │  requirepass)   │    (аудит, события)     │
│   хранилище) │  кэш, сессии,   │                         │
│              │  blacklist,     │                         │
│              │  rate limit     │                         │
└──────────────┴─────────────────┴─────────────────────────┘
```
2.2. Sequence диаграмма: логин пользователя
text
Client         Gateway         Auth Service      PostgreSQL       Redis
  │               │                  │                │             │
  │ POST /login   │                  │                │             │
  ├──────────────►│                  │                │             │
  │               │ POST /auth/login │                │             │
  │               ├─────────────────►│                │             │
  │               │                  │ SELECT user    │             │
  │               │                  ├───────────────►│             │
  │               │                  │ user data      │             │
  │               │                  │◄───────────────┤             │
  │               │                  │                │             │
  │               │                  │ verify password│             │
  │               │                  │ (Argon2)       │             │
  │               │                  │                │             │
  │               │                  │ INSERT refresh │             │
  │               │                  ├───────────────►│             │
  │               │                  │                │             │
  │               │                  │ SET blacklist? │             │
  │               │                  │ (если logout)  ├─────────────►│
  │               │                  │                │             │
  │               │   access+refresh │                │             │
  │               │◄─────────────────┤                │             │
  │               │                  │                │             │
  │   200 + tokens│                  │                │             │
  │◄──────────────┤                  │                │             │
  │               │                  │                │             │
2.3. Sequence диаграмма: проверка токена на Gateway (без вызова Auth Service)
text
Client         Gateway                    Redis           Microservice
  │               │                         │                   │
  │ GET /orders   │                         │                   │
  │ (JWT in       │                         │                   │
  │  Bearer)      │                         │                   │
  ├──────────────►│                         │                   │
  │               │                         │                   │
  │               │ 1. Проверить подпись JWT │                   │
  │               │    (локально, public key)│                   │
  │               │                         │                   │
  │               │ 2. Проверить в Redis    │                   │
  │               │    blacklist (опционально)│                 │
  │               ├────────────────────────►│                   │
  │               │      not blacklisted    │                   │
  │               │◄────────────────────────┤                   │
  │               │                         │                   │
  │               │ 3. Проверить permission │                   │
  │               │    из payload JWT       │                   │
  │               │    (orders.read)        │                   │
  │               │                         │                   │
  │               │ 4. Сформировать headers │                   │
  │               │    + HMAC подпись       │                   │
  │               │                         │                   │
  │               │                         │ GET /orders       │
  │               │                         │ X-User-Id: 123    │
  │               │                         │ X-Signature: HMAC │
  │               │                         ├──────────────────►│
  │               │                         │                   │
  │               │                         │   check signature │
  │               │                         │◄──────────────────┤
  │               │                         │                   │
  │   200 OK      │                         │                   │
  │◄──────────────┤                         │                   │
3. Модель данных и ER-диаграмма
3.1. Схема базы данных (PostgreSQL)
sql
-- Пользователи
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),  -- NULL для OAuth пользователей
    full_name VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE
);

-- Роли (с поддержкой иерархии)
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    parent_role_id UUID REFERENCES roles(id) ON DELETE SET NULL,  -- HRBAC
    level INT DEFAULT 0,  -- для быстрой сортировки
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Разрешения
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource VARCHAR(100) NOT NULL,    -- 'orders', 'users', 'reports'
    action VARCHAR(50) NOT NULL,       -- 'read', 'write', 'delete', 'manage'
    description TEXT,
    UNIQUE(resource, action)
);

-- Связь ролей с разрешениями (многие ко многим)
CREATE TABLE role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    granted_by UUID REFERENCES users(id),
    PRIMARY KEY (role_id, permission_id)
);

-- Связь пользователей с ролями
CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);

-- OAuth аккаунты (связь с внешними провайдерами)
CREATE TABLE oauth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,      -- 'google', 'telegram', 'vk'
    provider_user_id VARCHAR(255) NOT NULL,  -- ID в системе провайдера
    email_from_provider VARCHAR(255),
    access_token TEXT,                   -- зашифрованный
    refresh_token TEXT,                  -- зашифрованный
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

-- Refresh токены (с поддержкой ротации)
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash VARCHAR(255) UNIQUE NOT NULL,  -- хэш токена (не храним plain)
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255),             -- fingerprint устройства
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    replaced_by_token_id UUID,           -- для ротации
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Аудит безопасности (не критичные события, можно партиционировать)
CREATE TABLE security_audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,     -- 'login', 'logout', 'password_change'
    status VARCHAR(20) NOT NULL,         -- 'success', 'failure'
    ip_address INET,
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- MFA/TOTP секреты пользователей
CREATE TABLE user_mfa_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_key VARCHAR(255) NOT NULL,    -- зашифрованный TOTP secret (AES-256-GCM)
    is_enabled BOOLEAN DEFAULT false,
    backup_codes TEXT[],                 -- хэши backup-кодов (SHA-256 + соль)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    enabled_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id)
);

-- Сессии пользователей (для управления устройствами)
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_id UUID REFERENCES refresh_tokens(id) ON DELETE CASCADE,
    device_id VARCHAR(255),
    device_name VARCHAR(255),            -- 'Chrome on macOS', 'iPhone Safari'
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT true,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE
);

-- Создание индексов для производительности
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_last_login ON users(last_login_at);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_oauth_accounts_provider ON oauth_accounts(provider, provider_user_id);
CREATE INDEX idx_audit_user_time ON security_audit_log(user_id, created_at);
CREATE INDEX idx_audit_event_time ON security_audit_log(event_type, created_at);
CREATE INDEX idx_mfa_user_id ON user_mfa_secrets(user_id);
CREATE INDEX idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_sessions_active ON user_sessions(user_id, is_active);
3.2. ER-диаграмма
text
┌─────────────┐         ┌──────────────┐         ┌─────────────────┐
│   users     │         │  user_roles  │         │     roles       │
├─────────────┤         ├──────────────┤         ├─────────────────┤
│ id (PK)     │────────<│ user_id (FK) │         │ id (PK)         │
│ email       │         │ role_id (FK) │>────────│ name            │
│ password_hash│         └──────────────┘         │ parent_role_id(FK)►┐
│ ...         │                                    │ level             │  │
└─────────────┘                                    └─────────────────┘  │
       │                                                        │        │
       │                                              ┌─────────┘        │
       │                                              ▼                  │
       │                                      ┌─────────────────┐        │
       │                                      │ role_permissions│        │
       │                                      ├─────────────────┤        │
       │                                      │ role_id (FK)    │        │
       │                                      │ permission_id(FK)│       │
       │                                      └─────────────────┘        │
       │                                              │                  │
       │                                              ▼                  │
       │                                      ┌─────────────────┐        │
       │                                      │  permissions    │        │
       │                                      ├─────────────────┤        │
       │                                      │ id (PK)         │        │
       │                                      │ resource        │        │
       │                                      │ action          │        │
       │                                      └─────────────────┘        │
       │                                                                │
       ├─────────────────────────────────────────────────────────────────┘
       │
       ├──────────────┐              ┌──────────────────┐
       │              │              │ refresh_tokens   │
       │              │              ├──────────────────┤
       │              │              │ id (PK)          │
       │              │              │ token_hash       │
       │              │              │ user_id (FK)     │
       │              │              │ device_id        │
       │              │              │ expires_at       │
       │              │              └──────────────────┘
       │              │
       │              └──────────────┐
       │                             │
       ▼                             ▼
┌─────────────────┐          ┌──────────────────┐
│oauth_accounts   │          │security_audit_log│
├─────────────────┤          ├──────────────────┤
│ id (PK)         │          │ id (PK)          │
│ user_id (FK)    │          │ user_id (FK)     │
│ provider        │          │ event_type       │
│ provider_user_id│          │ status           │
└─────────────────┘          └──────────────────┘
3.3. Redis структуры данных
redis
# Blacklist access tokens (при logout / смене пароля)
SET "blacklist:access:{jti}" "user_id:{id}" EX 900  # 15 минут

# Rate limiting (sliding window)
INCR "ratelimit:login:{ip}" EX 60
# После 5 неудачных попыток
SET "ratelimit:block:{ip}" "1" EX 300  # блок 5 минут

# OAuth state (anti-CSRF)
SET "oauth:state:{state}" "{provider,redirect_uri}" EX 600

# User sessions cache (для быстрого /me)
HSET "user:session:{user_id}" "roles" "admin,user" "permissions" "orders.read,users.manage"
EXPIRE "user:session:{user_id}" 300

# Device fingerprint cache (для refresh token)
SET "device:{fingerprint}" "{device_info}" EX 86400
4. Компоненты и их ответственность
4.1. Auth Service (Python + FastAPI)
Основные модули:

Модуль	Ответственность	Технологии
API Layer	Обработка HTTP запросов, валидация	FastAPI, Pydantic
Auth Core	Логика аутентификации, хэширование	Argon2, python-jose
Token Manager	JWT generation/validation, refresh rotation	JWT (RS256), Redis
OAuth Integrator	Адаптеры для Google, Telegram, VK	Authlib, httpx
RBAC Engine	Проверка прав, иерархия ролей	Recursive CTE, ltree
Rate Limiter	Защита от брутфорса, DDoS	Redis + sliding window
Audit Logger	Логирование событий	Kafka / asyncpg
Metrics Exporter	Prometheus метрики	prometheus-fastapi
DB Migrations	Управление схемой БД, миграции	Alembic, asyncpg
4.2. API Gateway (Node.js / PHP)
Функции, связанные с Auth Service:

javascript
// Пример middleware на Gateway (Node.js + express-gateway)
async function authMiddleware(req, res, next) {
  // 1. Извлечь JWT из заголовка Authorization
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token && !isPublicRoute(req.path)) {
    return res.status(401).json(errorResponse(401, 'Missing token'));
  }
  
  // 2. Проверить подпись и срок действия (локально, через JWKS)
  try {
    const payload = await verifyJWT(token, jwksUrl);
    
    // 3. Проверить blacklist (опционально, только для sensitive операций)
    if (await isTokenBlacklisted(payload.jti)) {
      return res.status(401).json(errorResponse(401, 'Token revoked'));
    }
    
    // 4. Проверить permission для endpoint'а
    const requiredPermission = getRequiredPermission(req.method, req.path);
    if (requiredPermission && !payload.permissions.includes(requiredPermission)) {
      return res.status(403).json(errorResponse(403, 'Insufficient permissions'));
    }
    
    // 5. Сформировать внутренние headers с подписью
    const headers = {
      'X-User-Id': payload.sub,
      'X-User-Roles': payload.roles.join(','),
      'X-User-Permissions': payload.permissions.join(','),
      'X-User-Email': payload.email
    };
    
    // HMAC-SHA256 подпись для защиты от подмены
    const signaturePayload = `${payload.sub}:${payload.roles.join(',')}`;
    headers['X-Signature'] = hmacSha256(secretKey, signaturePayload);
    
    req.internalHeaders = headers;
    next();
  } catch (err) {
    return res.status(401).json(errorResponse(401, 'Invalid token'));
    }
  }
}

Приложение C: Email-сервис

C.1. Архитектура

Email-сервис — отдельный микросервис, общающийся с Auth Service через Kafka/RabbitMQ.
Auth Service не отправляет письма напрямую, а публикует события.

```
Auth Service ──publish──► Kafka Topic: "email.events"
                                    │
                                    ▼
                          Email Service (consumer)
                                    │
                                    ▼
                          SMTP Provider (SendGrid, AWS SES, Postmark)
```

C.2. Формат сообщений Kafka

```json
{
  "event_id": "evt_abc123",
  "event_type": "email.verification_code",
  "timestamp": "2026-05-11T10:30:00Z",
  "payload": {
    "to": "user@example.com",
    "template": "verification_code",
    "variables": {
      "code": "123456",
      "expires_minutes": 15
    },
    "locale": "ru"
  },
  "metadata": {
    "request_id": "req_xyz789",
    "retry_count": 0,
    "max_retries": 3
  }
}
```

Типы событий:

| event_type | Описание | Template |
|------------|----------|----------|
| `email.verification_code` | Код подтверждения email | verification_code |
| `email.password_reset` | Код сброса пароля | password_reset |
| `email.password_changed` | Уведомление о смене пароля | password_changed |
| `email.mfa_enabled` | Уведомление о включении MFA | mfa_enabled |
| `email.account_locked` | Уведомление о блокировке аккаунта | account_locked |
| `email.new_login` | Уведомление о новом входе | new_login |

C.3. Требования к Email-сервису

- Асинхронная отправка (не блокирует Auth Service)
- Retry с exponential backoff (3 попытки)
- Dead letter queue для недоставленных писем
- Rate limiting на уровне SMTP провайдера
- Поддержка шаблонов (Jinja2 / Handlebars)
- Локализация (ru, en)
- Логирование статуса доставки

C.4. Redis для кодов подтверждения

```redis
# Код подтверждения email
SET "email:verify:{email}" "{code}" EX 900  # 15 минут

# Код сброса пароля
SET "email:reset:{email}" "{code}" EX 900   # 15 минут

# Счётчик отправок (rate limiting)
INCR "email:send_count:{email}" EX 3600     # 1 час
```

Приложение D: Ротация RSA-ключей

D.1. Стратегия

- Ключи ротируются каждые 90 дней
- Поддерживается 2 активных ключа одновременно (current + previous)
- JWKS endpoint отдаёт оба публичных ключа
- Grace period: старые токены, подписанные previous ключом, валидны ещё 15 минут после ротации

D.2. Хранение ключей

```
/run/secrets/
├── jwt_private_current.pem    # Текущий приватный ключ
├── jwt_public_current.pem     # Текущий публичный ключ
├── jwt_private_previous.pem   # Предыдущий приватный ключ
├── jwt_public_previous.pem    # Предыдущий публичный ключ
└── jwt_key_metadata.json      # Метаданные (kid, created_at, expires_at)
```

jwt_key_metadata.json:
```json
{
  "keys": [
    {
      "kid": "key-2026-q2-v1",
      "created_at": "2026-04-01T00:00:00Z",
      "expires_at": "2026-06-30T00:00:00Z",
      "status": "current"
    },
    {
      "kid": "key-2026-q1-v1",
      "created_at": "2026-01-01T00:00:00Z",
      "expires_at": "2026-04-01T00:15:00Z",
      "status": "previous"
    }
  ]
}
```

D.3. Процедура ротации

```
1. Сгенерировать новую пару RSA-2048 ключей
2. Записать новый ключ как "pending" в metadata
3. Текущий ключ → previous
4. Новый ключ → current
5. Обновить JWKS endpoint (отдаёт оба публичных ключа)
6. Подождать 15 минут (grace period для старых токенов)
7. Удалить previous приватный ключ
8. Обновить metadata: previous → expired
```

D.4. JWKS endpoint при ротации

```json
GET /.well-known/jwks.json

Response:
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-2026-q2-v1",
      "use": "sig",
      "alg": "RS256",
      "n": "base64url_new_modulus",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "kid": "key-2026-q1-v1",
      "use": "sig",
      "alg": "RS256",
      "n": "base64url_old_modulus",
      "e": "AQAB"
    }
  ]
}
```

D.5. Автоматизация

- CronJob в Kubernetes запускает скрипт ротации за 7 дней до истечения
- Alert в Prometheus за 30 дней до истечения ключа
- Ручная ротация через POST /admin/keys/rotate (требует super_admin)

D.6. Откат

Если новый ключ вызывает проблемы:
1. Вернуть previous ключ в статус current
2. Обновить JWKS (убрать новый ключ)
3. Сгенерировать новую пару позже

Приложение E: Схема сообщений аудита (Kafka/RabbitMQ)

E.1. Формат событий

```json
{
  "event_id": "audit_abc123",
  "event_type": "auth.login.success",
  "timestamp": "2026-05-11T10:30:00Z",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
  "details": {
    "auth_method": "password",
    "device_id": "device_fingerprint",
    "mfa_used": true
  },
  "request_id": "req_xyz789"
}
```

E.2. Типы событий аудита

| Event Type | Описание | Severity |
|------------|----------|----------|
| `auth.login.success` | Успешный логин | INFO |
| `auth.login.failure` | Неудачный логин | WARN |
| `auth.login.brute_force` | Подозрение на брутфорс | CRITICAL |
| `auth.logout` | Выход из системы | INFO |
| `auth.password.change` | Смена пароля | WARN |
| `auth.password.reset` | Сброс пароля | WARN |
| `auth.email.change` | Смена email | WARN |
| `auth.email.verify` | Подтверждение email | INFO |
| `auth.mfa.enable` | Включение MFA | WARN |
| `auth.mfa.disable` | Отключение MFA | WARN |
| `auth.role.assign` | Назначение роли | WARN |
| `auth.role.revoke` | Отзыв роли | WARN |
| `auth.oauth.link` | Связывание OAuth провайдера | INFO |
| `auth.oauth.unlink` | Отвязывание OAuth провайдера | WARN |
| `auth.session.revoke` | Отзыв сессии | WARN |
| `auth.token.refresh` | Обновление токена | INFO |
| `auth.account.lock` | Блокировка аккаунта | WARN |
| `auth.account.unlock` | Разблокировка аккаунта | INFO |
| `auth.account.delete` | Удаление аккаунта | CRITICAL |

E.3. Kafka Topic конфигурация

```
Topic: auth.audit.events
Partitions: 6
Replication factor: 3
Retention: 90 дней
Compaction: false
```

Приложение F: Graceful Shutdown

F.1. Процесс завершения

```
1. Получение SIGTERM (Kubernetes termination grace period: 30s)
2. Stop accepting new connections (health check → 503)
3. Wait for in-flight requests to complete (max 15s)
4. Close database connection pool
5. Close Redis connection pool
6. Flush audit events to Kafka/RabbitMQ
7. Export final Prometheus metrics
8. Exit with code 0
```

F.2. Конфигурация

```python
# FastAPI lifespan
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db.connect()
    await redis.connect()
    yield
    # Shutdown
    await audit_logger.flush()
    await redis.close()
    await db.disconnect()
```

F.3. Kubernetes deployment

```yaml
lifecycle:
  preStop:
    exec:
      command: ["/bin/sh", "-c", "sleep 5"]  # дать Gateway время убрать из endpoint list

terminationGracePeriodSeconds: 30

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8000
  periodSeconds: 5
  failureThreshold: 3
```

Приложение G: HaveIBeenPwned интеграция

G.1. K-Anonymity Flow

При регистрации и смене пароля пароль проверяется по базе утекших паролей
через HIBP API с использованием k-anonymity (сервер не получает сам пароль):

```
1. Пользователь вводит пароль: "SecurePass123!"
2. Вычисляем SHA-1 хэш: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
3. Берём первые 5 символов (prefix): 5BAA6
4. Запрос к HIBP: GET https://api.pwnedpasswords.com/range/5BAA6
5. HIBP возвращает список суффиксов с количеством утечек:
   1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345
   ...
6. Сравниваем наш суффикс с полученным списком
7. Если найден — reject пароль с сообщением:
   "This password has been compromised in a data breach. Please choose another."
```

G.2. Требования

- Timeout запроса: 5 секунд
- Fallback: если HIBP недоступен — пропустить проверку (log warning)
- Rate limit HIBP API: 10 запросов в минуту (бесплатный тариф)
- Кэширование популярных prefix в Redis (TTL 1 час)

G.3. Интеграция в flow регистрации

```
POST /auth/register
  │
  ├─► Валидация формата пароля (Pydantic)
  │
  ├─► Проверка по HIBP (k-anonymity)
  │     ├─► Compromised → 400 Bad Request
  │     └─► Clean → продолжить
  │
  ├─► Argon2id хэширование
  │
  └─► Создание пользователя в БД
```
7.2. Refresh Token
Хранение:

Только хэш в PostgreSQL (token_hash = SHA256(refresh_token))

Связь с устройством (device_id)

Ротация:

text
1. Client запрашивает /auth/refresh
2. Auth Service проверяет refresh token (дехэширует и ищет в БД)
3. Если валидный:
   - Помечает старый токен как revoked
   - Генерирует новый refresh token
   - Генерирует новый access token
4. Возвращает оба токена клиенту
Важно: При ротации старый refresh token становится невалидным (одноразовое использование).

7.3. Алгоритмы шифрования
Данные	Алгоритм	Ключ	Хранение
Пароли	Argon2id	-	Хэш в БД
JWT Access	RS256 (RSA)	2048 bit	Подпись приватным ключом
OAuth токены	AES-256-GCM	256 bit	Зашифровано в БД
Внутренние headers	HMAC-SHA256	256 bit	Подпись на Gateway
Данные в Redis	-	-	Без шифрования (trusted network)
7.4. JWKS Endpoint
text
GET /.well-known/jwks.json

Response:
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-2026-v1",
      "use": "sig",
      "alg": "RS256",
      "n": "base64url_encoded_modulus",
      "e": "AQAB"
    }
  ]
}
Применение: API Gateway скачивает публичный ключ для проверки JWT без вызова Auth Service.

8. API спецификация (OpenAPI 3.1)
8.1. Базовые эндпоинты
POST /auth/register
Регистрация нового пользователя.

Request:

json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "full_name": "John Doe"
}
Response (201 Created):

json
{
  "message": "User registered successfully. Please verify your email.",
  "verification_code_sent": true
}
Errors:

400 - Invalid email or password format

409 - Email already exists

429 - Too many registration attempts

POST /auth/login
Аутентификация по email и паролю.

**Защита:** после 3 неудачных попыток логина с одного IP требуется CAPTCHA (X-Captcha-Token).
После 10 неудачных попыток — временная блокировка на 5 минут (Redis key: `ratelimit:block:{ip}`).

Request:

json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "device_id": "optional_device_fingerprint"
}
Response (200 OK) — MFA не включён:

json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "full_name": "John Doe",
    "roles": ["user"],
    "permissions": ["orders:read"]
  }
}

**Передача refresh token:** не включается в тело ответа, а устанавливается через **httpOnly Secure SameSite=Strict cookie** с именем `refresh_token`. Для native/mobile клиентов refresh token возвращается в теле ответа в поле `refresh_token` (детекция по заголовку `X-Client-Type: native`).
Response (200 OK) — MFA включён (требуется TOTP):

json
{
  "mfa_required": true,
  "mfa_token": "mfa_temp_abc123def456",
  "message": "TOTP code required"
}

**mfa_token:** временный одноразовый токен, подтверждающий успешный первый этап аутентификации.
- **Формат:** случайная строка длиной 32 символа (secrets.token_urlsafe(32))
- **Хранение:** Redis, ключ `"mfa:session:{mfa_token}"`, значение — `user_id + device_id`
- **TTL:** 5 минут (300 секунд)
- **Защита:** одноразовое использование (удаляется из Redis после первого успешного или неудачного подтверждения); rate limit 3 попытки на mfa_token
- **Аудит:** неудачные попытки логируются как `auth.login.mfa_failure`

POST /auth/login/mfa
Подтверждение логина TOTP-кодом (если MFA включён).

Request:

json
{
  "mfa_token": "temp_mfa_token_abc123",
  "totp_code": "123456"
}
Response (200 OK):

json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "ref_550e8400e29b41d4a716446655440000",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "full_name": "John Doe",
    "roles": ["user"],
    "permissions": ["orders:read"]
  }
}
Errors:

401 - Invalid TOTP code

401 - MFA token expired (5 минут)

POST /auth/refresh
Обновление access token.

Request:

json
{
  "refresh_token": "ref_550e8400e29b41d4a716446655440000"
}
Response (200 OK):

json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "ref_new_123456789abcdef",
  "expires_in": 900
}
Errors:

401 - Invalid or expired refresh token

401 - Token revoked (used before)

POST /auth/logout
Выход из системы (отзыв текущих токенов и сессии).

Request (refresh token в теле или httpOnly cookie):

json
{
  "refresh_token": "ref_550e8400e29b41d4a716446655440000"
}
Response (204 No Content)
**Refresh token** передаётся через:
1. **httpOnly Secure SameSite=Strict cookie** (рекомендуемый способ для web-клиентов) — устанавливается при логине и refresh
2. **Тело запроса** (для mobile/native клиентов, где cookies недоступны)

GET /auth/me
Получение информации о текущем пользователе.

Headers:

text
Authorization: Bearer {access_token}
Response (200 OK):

json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "full_name": "John Doe",
  "is_verified": true,
  "roles": ["user", "manager"],
  "permissions": ["orders:read", "orders:write", "reports:view"],
  "oauth_providers": ["google", "telegram"],
  "last_login_at": "2026-05-11T10:30:00Z",
  "created_at": "2025-01-01T00:00:00Z"
}
8.2. OAuth эндпоинты
GET /auth/oauth/{provider}
Инициировать OAuth flow.

Path parameters:

provider - google | telegram | vk

Query parameters:

redirect_uri - URL для возврата после логина (опционально)

Response (302 Redirect)
Перенаправление на страницу авторизации провайдера.

GET /auth/oauth/{provider}/callback
Callback URL для OAuth провайдера (обрабатывается автоматически).

**Защита:** используется PKCE (Proof Key for Code Exchange) — code_challenge + code_verifier
для предотвращения CSRF-атак и перехвата authorization code.

Response (302 Redirect)
Перенаправление на frontend с токенами во фрагменте URL (#):

text
https://app.example.com/auth/callback#access_token=...&refresh_token=...
8.3. Password management
POST /auth/change-email
Смена email (требует аутентификации и подтверждения нового email через код).

Headers:

text
Authorization: Bearer {access_token}
Request:

json
{
  "new_email": "newemail@example.com"
}
Response (200 OK):

json
{
  "message": "Verification code sent to new email.",
  "verification_sent": true
}
Errors:

400 - Invalid email format

409 - Email already in use

POST /auth/confirm-email
Подтверждение нового email.

Request:

json
{
  "email": "newemail@example.com",
  "code": "123456"
}
Response (200 OK):

json
{
  "message": "Email confirmed successfully."
}

POST /auth/change-password
Смена пароля (требует аутентификации).

Headers:

text
Authorization: Bearer {access_token}
Request:

json
{
  "old_password": "CurrentPass123!",
  "new_password": "NewSecurePass456!"
}
Response (200 OK):

json
{
  "message": "Password changed successfully. All existing tokens have been revoked."
}
POST /auth/forgot-password
Запрос сброса пароля.

Request:

json
{
  "email": "user@example.com"
}
Response (200 OK):

json
{
  "message": "If the email exists, a reset code has been sent."
}
POST /auth/reset-password
Сброс пароля с кодом подтверждения.

Request:

json
{
  "email": "user@example.com",
  "reset_code": "123456",
  "new_password": "NewSecurePass789!"
}
Response (200 OK):

json
{
  "message": "Password reset successfully."
}
8.5. MFA/TOTP
POST /auth/mfa/setup
Инициировать настройку MFA (требует аутентификации).

Headers:

text
Authorization: Bearer {access_token}
Response (200 OK):

json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "otpauth://totp/AuthService:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AuthService",
  "backup_codes": ["12345678", "87654321", "..."]
}

POST /auth/mfa/verify
Подтвердить настройку MFA кодом из TOTP-приложения.

Request:

json
{
  "totp_code": "123456"
}
Response (200 OK):

json
{
  "message": "MFA enabled successfully.",
  "is_enabled": true
}
Errors:

400 - Invalid TOTP code

POST /auth/mfa/recover
Восстановление доступа к аккаунту с помощью backup-кода (при утере TOTP-устройства).

Request:

json
{
  "email": "user@example.com",
  "backup_code": "12345678",
  "new_device_id": "optional_new_device_fingerprint"
}
Response (200 OK):

json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "full_name": "John Doe",
    "roles": ["user"],
    "permissions": ["orders:read"]
  }
}
Errors:

401 - Invalid or already used backup code

401 - Backup codes exhausted (все коды использованы — требуется ручное восстановление через поддержку)

**Backup-коды:**
- **Количество:** 8 кодов при генерации
- **Формат:** 8 цифр каждый
- **Хранение:** SHA-256 хэш с уникальной солью (bcrypt-style, без Argon2id для снижения нагрузки)
- **Одноразовое использование:** после использования код удаляется из списка
- **Исчерпание:** при использовании последнего кода пользователь получает уведомление с предложением сгенерировать новые
- **Аудит:** каждое использование backup-кода логируется как `auth.mfa.backup_used` (WARN)

POST /auth/mfa/disable
Отключить MFA (требует подтверждения текущим TOTP-кодом).

Request:

json
{
  "totp_code": "654321"
}
Response (200 OK):

json
{
  "message": "MFA disabled successfully.",
  "is_enabled": false
}

GET /auth/mfa/status
Проверить статус MFA.

Response (200 OK):

json
{
  "is_enabled": true,
  "enabled_at": "2026-05-11T10:30:00Z"
}

8.7. GDPR и Self-Service
Эндпоинты для выполнения требований GDPR (право на забвение, экспорт данных) и self-service пользователя.

DELETE /auth/account
Удаление аккаунта и всех связанных данных (право на забвение).

Headers:

text
Authorization: Bearer {access_token}
Request:

json
{
  "password": "CurrentPass123!",
  "confirmation": "DELETE"
}
Response (200 OK):

json
{
  "message": "Account scheduled for deletion. All data will be erased within 72 hours.",
  "deletion_scheduled_at": "2026-05-18T10:30:00Z"
}
Errors:

400 - Invalid password or confirmation text

GET /auth/export-data
Экспорт всех данных пользователя в JSON.

Headers:

text
Authorization: Bearer {access_token}
Response (200 OK):

json
{
  "export_id": "exp_abc123",
  "expires_at": "2026-05-19T10:30:00Z",
  "data": {
    "user": {
      "email": "user@example.com",
      "full_name": "John Doe",
      "created_at": "2025-01-01T00:00:00Z"
    },
    "oauth_providers": ["google"],
    "sessions": [
      {
        "device_name": "Chrome on macOS",
        "created_at": "2026-05-01T08:00:00Z"
      }
    ],
    "audit_log": [
      {
        "event_type": "auth.login.success",
        "timestamp": "2026-05-11T10:30:00Z"
      }
    ]
  }
}
Errors:

401 - Authentication required

POST /auth/request-account-deletion
Запрос полного удаления аккаунта (альтернативный flow для верификации через email).

Request:

json
{
  "password": "CurrentPass123!"
}
Response (200 OK):

json
{
  "message": "Deletion confirmation sent to your email.",
  "confirmation_sent": true
}

8.6. Session Management
GET /auth/sessions
Список активных сессий пользователя (требует аутентификации).

Response (200 OK):

json
{
  "sessions": [
    {
      "id": "session-uuid-1",
      "device_name": "Chrome on macOS",
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0 ...",
      "last_seen_at": "2026-05-11T10:30:00Z",
      "created_at": "2026-05-01T08:00:00Z",
      "is_current": true
    },
    {
      "id": "session-uuid-2",
      "device_name": "iPhone Safari",
      "ip_address": "10.0.0.5",
      "user_agent": "Mozilla/5.0 ...",
      "last_seen_at": "2026-05-10T18:00:00Z",
      "created_at": "2026-04-28T12:00:00Z",
      "is_current": false
    }
  ]
}

DELETE /auth/sessions/{session_id}
Отзыв конкретной сессии.

Response (204 No Content)

DELETE /auth/sessions/all
Отзыв всех сессий кроме текущей (при смене пароля, подозрении на взлом).

Response (204 No Content)

8.4. Административные эндпоинты
GET /admin/users
Список пользователей (пагинация, фильтры).

Headers:

text
Authorization: Bearer {access_token}  # requires users:read permission
Query parameters:

page - номер страницы (default: 1)

size - элементов на странице (default: 20, max: 100)

search - поиск по email или имени

is_active - фильтр по статусу (true/false)

Response (200 OK):

json
{
  "items": [
    {
      "id": "uuid",
      "email": "user@example.com",
      "full_name": "John Doe",
      "is_active": true,
      "is_verified": true,
      "last_login_at": "2026-05-11T10:30:00Z"
    }
  ],
  "total": 1250,
  "page": 1,
  "size": 20,
  "pages": 63
}
PUT /admin/users/{user_id}/roles
Назначить роли пользователю.

Request:

json
{
  "role_ids": ["role-uuid-1", "role-uuid-2"]
}
Response (200 OK):

json
{
  "message": "Roles updated successfully",
  "roles": ["user", "manager"]
}
9. Интеграция с API Gateway
9.1. Формат внутренних headers
Gateway добавляет заголовки для всех запросов к микросервисам:

Header	Пример	Описание
X-User-Id	550e8400-e29b-41d4-a716-446655440000	UUID пользователя
X-User-Email	user@example.com	Email пользователя
X-User-Roles	user,manager,admin	Список ролей (через запятую)
X-User-Permissions	orders:read,reports:view	Список разрешений
X-Signature	hmac_sha256_hash	Подпись всех данных
X-Request-Id	req_abc123	ID запроса для трейсинга
X-Auth-Time	1747020000	Время аутентификации (Unix timestamp)
9.2. Защита от подмены headers
Проблема: Злоумышленник может напрямую обратиться к микросервису и подставить заголовки.

Решение: HMAC подпись.

python
# На Gateway (генерация подписи)
def generate_internal_headers(user_id, roles, permissions):
    payload = f"{user_id}:{roles}:{permissions}"
    signature = hmac.new(
        INTERNAL_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return {
        "X-User-Id": user_id,
        "X-User-Roles": roles,
        "X-User-Permissions": permissions,
        "X-Signature": signature
    }

# В микросервисе (проверка)
def verify_internal_request(headers):
    user_id = headers.get("X-User-Id")
    roles = headers.get("X-User-Roles", "")
    permissions = headers.get("X-User-Permissions", "")
    signature = headers.get("X-Signature")
    
    payload = f"{user_id}:{roles}:{permissions}"
    expected = hmac.new(INTERNAL_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(signature, expected):
        raise Forbidden("Invalid internal request signature")
    
    return {"user_id": user_id, "roles": roles.split(','), "permissions": permissions.split(',')}
9.3. Rate limiting на Gateway
Gateway также применяет rate limiting:

yaml
rate_limits:
  - path: /auth/login
    method: POST
    limit: 5 per minute per IP
    burst: 10
  
  - path: /auth/register
    method: POST
    limit: 3 per hour per IP
    burst: 5
  
  - path: /auth/refresh
    method: POST
    limit: 30 per minute per user
    burst: 50

**Конфигурация rate limit:** лимиты задаются через переменные окружения:
- `RATE_LIMIT_LOGIN_PER_IP` (default: 5/min)
- `RATE_LIMIT_REGISTER_PER_IP` (default: 3/hour)
- `RATE_LIMIT_REFRESH_PER_USER` (default: 30/min)
- `RATE_LIMIT_MFA_ATTEMPTS` (default: 3/token)
- `RATE_LIMIT_EMAIL_SEND_PER_EMAIL` (default: 5/hour)

Изменение лимитов не требует передеплоя — значения читаются при старте из env и могут быть обновлены через rolling restart.

9.4. CORS политика

Auth Service должен поддерживать CORS для взаимодействия с frontend:

```yaml
cors:
  allowed_origins:
    - "https://app.example.com"
    - "https://admin.example.com"
  allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  allowed_headers: ["Authorization", "Content-Type", "X-Request-Id"]
  expose_headers: ["X-Request-Id"]
  allow_credentials: true
  max_age: 3600
```

**Конфигурация:** через переменные окружения `CORS_ALLOWED_ORIGINS` (список через запятую),
`CORS_ALLOW_CREDENTIALS` (true/false). Для development допускается `CORS_ALLOWED_ORIGINS=*`.

10. Безопасность
10.1. Криптографические требования
Требование	Реализация
HTTPS everywhere	TLS 1.3, HSTS, безопасные шифры (ECDHE-RSA-AES256-GCM-SHA384)
JWT подпись	RS256 (RSA 2048-bit), ротация ключей каждые 90 дней
Хэширование паролей	Argon2id (memory=102400, time=3, parallelism=4)
Секреты в env	Никаких секретов в коде или репозитории
Защита от CSRF	State параметр в OAuth, SameSite cookies
Защита от XSS	Content-Security-Policy, httpOnly Secure SameSite=Strict cookies (для refresh)
Политика паролей	См. 10.5
10.2. Мониторинг безопасности
Логирование обязательных событий:

Успешный/неуспешный логин (с IP, user-agent)

Смена пароля

Смена email

Назначение ролей

OAuth связывание/отвязывание

Отзыв токенов (logout)

Alert правила:

10 неудачных логинов для одного пользователя за 1 минуту

100 неудачных логинов с одного IP за 1 минуту

Несколько разных OAuth провайдеров для одного пользователя за короткое время

Смена пароля сразу после логина (подозрение на взлом)

10.3. Защита от атак
Атака	Защита
Brute force	Rate limiting + временная блокировка + CAPTCHA (Google reCAPTCHA v3 или Cloudflare Turnstile)
Credential stuffing	Проверка по haveibeenpwned API (k-anonymity, см. Приложение G) при регистрации и смене пароля
Refresh token theft	Ротация + привязка к устройству + отзыв всех токенов при подозрении
JWT replay	Короткий TTL + blacklist при logout
Man-in-the-middle	Mutual TLS (mTLS) между сервисами
Header injection	HMAC подпись на Gateway
CAPTCHA bypass	Серверная валидация токена (не доверять client-side); rate limit на верификацию

**Интеграция CAPTCHA:**
- **Провайдер:** Cloudflare Turnstile (рекомендуется, privacy-friendly, не требует согласия пользователя) или Google reCAPTCHA v3 (как fallback)
- **Где применяется:** `/auth/login` (после 3 неудачных попыток), `/auth/register`, `/auth/forgot-password`
- **Токен CAPTCHA** передаётся в заголовке `X-Captcha-Token`
- **Серверная верификация:** Auth Service проверяет токен через API провайдера
- **Fallback:** при недоступности CAPTCHA-провайдера — пропустить, залогировать warning, усилить rate limiting
- **Конфигурация:** `CAPTCHA_PROVIDER` (turnstile | recaptcha | disabled), `CAPTCHA_SITE_KEY`, `CAPTCHA_SECRET_KEY`
10.4. Compliance
GDPR: Право на забвение (удаление всех данных пользователя)

PCI DSS: Если обрабатываются платежи - дополнительное логирование

HIPAA: Для медицинских данных - audit trail на 7 лет

10.5. Политика паролей

Требования к паролю при регистрации и смене пароля:

| Требование | Значение |
|------------|----------|
| Минимальная длина | 12 символов |
| Максимальная длина | 128 символов |
| Заглавные буквы | минимум 1 (A-Z) |
| Строчные буквы | минимум 1 (a-z) |
| Цифры | минимум 1 (0-9) |
| Спецсимволы | минимум 1 (!@#$%^&*()_+-=[]{}|;':\",./<>?) |
| Запрещённые паттерны | email пользователя, последовательные символы (abc, 123), повторяющиеся символы (aaa) |
| Проверка по HIBP | обязательна (k-anonymity, Приложение G) |
| Проверка по списку распространённых паролей | встроенный список top-10000 (избыточная проверка на случай недоступности HIBP) |
| История паролей | запрет на последние 5 использованных паролей |

**Реализация валидации:** Pydantic validator на уровне API Layer + серверная проверка
перед хэшированием.

11. Нефункциональные требования
11.1. Производительность
Метрика	Целевое значение	Нагрузочный тест
RPS (запросов/с)	5000+	k6 / Locust
Время ответа /auth/login	p95 < 500ms	10,000 запросов
Время ответа /auth/me	p95 < 50ms	50,000 запросов
Время ответа /auth/refresh	p95 < 100ms	50,000 запросов
Потребление RAM	< 512 MB per instance	-
Потребление CPU	< 2 cores per instance	-
11.2. Доступность и отказоустойчивость
text
Требования:
- Минимум 3 реплики Auth Service (в разных availability zones)
- PostgreSQL cluster (Patroni + 3 replicas) или управляемый сервис
- Redis cluster (sentinel или managed)
- Автоматический рестарт при падении (Kubernetes liveness/readiness probes)
Readiness probe:

yaml
GET /health/ready
Response: 200 OK {"status": "ready", "database": "connected", "redis": "connected"}
Liveness probe:

yaml
GET /health/alive
Response: 200 OK {"status": "alive"}
11.3. Мониторинг и observability
Метрики (Prometheus):

text
auth_login_total{status="success|failure"}
auth_login_mfa_total{status="success|failure"}
auth_refresh_total{status="success|failure"}
auth_tokens_issued_total
auth_active_sessions
auth_oauth_attempts{provider="google|telegram|vk"}
auth_db_query_duration_seconds
auth_redis_query_duration_seconds
auth_rate_limit_hits_total
auth_mfa_enabled_total
auth_mfa_backup_used_total
auth_sessions_revoked_total
Трейсинг (Jaeger/Zipkin):

Каждый запрос имеет X-Request-Id

Отслеживание всего пути: Gateway → Auth Service → DB/Redis → Auth Service → Gateway

Автоматическое логирование на каждый span

Логирование (ELK/Loki):

JSON формат с полями: timestamp, level, request_id, user_id, ip, message

Ротация логов: 30 дней хранения

Индексация: по user_id, request_id, timestamp

12. Критерии готовности
12.1. Функциональные критерии
Регистрация пользователя с валидацией пароля и email

Логин с email/паролем с защитой от брутфорса

Логин через OAuth (Google, Telegram, VK)

JWT access token с подписью RS256, TTL 15 минут

Refresh token с ротацией и отзывом

RBAC с поддержкой иерархических ролей

API для администраторов (управление ролями)

Сброс пароля через email

Полный logout с отзывом всех токенов

JWKS endpoint для API Gateway

HMAC подпись внутренних заголовков

Рейт лимитинг на критических эндпоинтах

Аудит всех критических событий

MFA/TOTP: настройка, подтверждение, отключение, login с TOTP-кодом

Session management: просмотр активных сессий, отзыв отдельных и всех сессий

12.2. Нефункциональные критерии
Производительность: 5000 RPS, p95 < 500ms для /auth/login, p95 < 50ms для /auth/me

Документация: Swagger UI + OpenAPI 3.1

Тесты: юнит-тесты (80% покрытие), интеграционные тесты (100% важных сценариев), e2e тесты (сценарии OAuth)

Мониторинг: Prometheus метрики + Grafana дашборды

Безопасность: Dependency scan, SAST (SonarQube), DAST (OWASP ZAP)

Деплой: Docker + docker-compose + Helm chart для K8s

Миграции: Alembic с автоматическими миграциями, откат

Graceful shutdown: Обработка сигналов SIGTERM, завершение текущих запросов

12.3. Интеграционные критерии
API Gateway может проверить JWT через JWKS

Микросервис проверяет HMAC подпись перед использованием headers

События аудита уходят в Kafka/RabbitMQ

Health checks корректно работают в K8s/Consul

Без stateful хранения (Redis для сессий, JWT stateless)

13. Roadmap и этапы
Этап 1: Базовая реализация (2 недели)
Проектирование БД, Alembic миграции

Регистрация, логин, JWT (RS256, JWKS endpoint)

Refresh token в БД, ротация

Session management (таблица user_sessions)

Базовые тесты (pytest)

Этап 2: OAuth, MFA и безопасность (2.5 недели)
Интеграция с Google, Telegram, VK

Argon2 для паролей

RS256 для JWT, JWKS endpoint

Rate limiting (Redis)

MFA/TOTP: setup, verify, disable, login с TOTP

HaveIBeenPwned интеграция (k-anonymity)

Этап 3: RBAC, сессии и администрирование (2 недели)
Модель ролей и разрешений

API для управления ролями

Проверка прав (декораторы FastAPI)

Session management API: просмотр, отзыв сессий

Email-сервис интеграция (Kafka events)

Этап 4: Интеграция и production (1.5 недели)
HMAC подпись для внутренних сервисов

Docker + docker-compose

Prometheus метрики

Логирование в JSON формате

Graceful shutdown

Load testing (k6)

Этап 5: Доработки и документация (1 неделя)
Swagger документация

Примеры интеграции с Gateway (Node.js, PHP)

Руководство по развертыванию

Security audit

Ротация RSA-ключей (автоматизация)

Приложение A: Пример docker-compose для разработки
yaml
version: '3.8'

services:
  auth-service:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://postgres:postgres@postgres:5432/auth_db
      - REDIS_URL=redis://:${REDIS_PASSWORD:-devpassword}@redis:6379
      - JWT_PRIVATE_KEY=/run/secrets/jwt_private_key
      - JWT_PUBLIC_KEY=/run/secrets/jwt_public_key
    depends_on:
      - postgres
      - redis
    secrets:
      - jwt_private_key
      - jwt_public_key
    deploy:
      replicas: 3

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: auth_db
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD:-devpassword}
    ports:
      - "6379:6379"
    environment:
      - REDIS_PASSWORD=${REDIS_PASSWORD:-devpassword}
    volumes:
      - redis_data:/data

  pgadmin:
    image: dpage/pgadmin4
    environment:
      PGADMIN_DEFAULT_EMAIL: admin@example.com
      PGADMIN_DEFAULT_PASSWORD: admin
    ports:
      - "5050:80"
    depends_on:
      - postgres

secrets:
  jwt_private_key:
    file: ./secrets/private.pem
  jwt_public_key:
    file: ./secrets/public.pem

volumes:
  postgres_data:
  redis_data:
Приложение B: Ключевые метрики для мониторинга
prometheus
# Grafana dashboard JSON (упрощенный)
{
  "dashboard": {
    "title": "Auth Service Monitoring",
    "panels": [
      {
        "title": "Login Success Rate",
        "expr": "rate(auth_login_total{status='success'}[5m]) / rate(auth_login_total[5m])"
      },
      {
        "title": "Request Duration (p95)",
        "expr": "histogram_quantile(0.95, rate(auth_request_duration_seconds_bucket[5m]))"
      },
      {
        "title": "Active Refresh Tokens",
        "expr": "auth_active_refresh_tokens"
      },
      {
        "title": "Rate Limit Hits",
        "expr": "rate(auth_rate_limit_hits_total[5m])"
      }
    ]
  }
}
