# Конфигурация

[← Оглавление](README.md)

Пакет приносит свой `config/uzairports.php` и работает на значениях по умолчанию — достаточно
заполнить `.env`:

```env
UZAIR_CLIENT_ID=your-client-id
UZAIR_CLIENT_SECRET=your-client-secret
UZAIR_CALLBACK_URL=https://your-app.com/auth/callback
```

Если нужно изменить сам файл, опубликуйте его:

```bash
php artisan vendor:publish --tag=uzairid-config
```

| Ключ | Переменная | По умолчанию | Назначение |
| --- | --- | --- | --- |
| `client_id` | `UZAIR_CLIENT_ID` | — | Идентификатор OAuth-клиента |
| `client_secret` | `UZAIR_CLIENT_SECRET` | — | Секрет OAuth-клиента |
| `redirect` | `UZAIR_CALLBACK_URL` | — | Адрес callback-маршрута |
| `host` | `UZAIR_HOST` | `https://my.uzairports.com` | Адрес UzAirports ID; меняется для стенда |
| `revoke_endpoint` | `UZAIR_REVOKE_ENDPOINT` | — | Эндпоинт RFC 7009 для отзыва refresh-токена |
| `logout_endpoint` | `UZAIR_LOGOUT_ENDPOINT` | `/api/v1/oauth/logout` | Эндпоинт для отзыва access-токена при logout |
| `user_endpoint` | `UZAIR_USER_ENDPOINT` | `/api/user` | Эндпоинт получения профиля пользователя |
| `revoke_on_prune` | `UZAIR_REVOKE_ON_PRUNE` | `true` | Отдавать ли гранты SSO при уборке брошенных входов |
| `revoke_on_single_session` | `UZAIR_REVOKE_ON_SINGLE_SESSION` | `true` | Отзывать ли гранты SSO при завершении других входов через `single_session` |
| `pkce` | `UZAIR_PKCE` | `true` | Привязывать ли код авторизации к одноразовому verifier |
| `scopes` | `UZAIR_SCOPES` | — | Запрашиваемые scope через пробел |
| `refresh_leeway` | `UZAIR_REFRESH_LEEWAY` | `60` | За сколько секунд до истечения обновлять токен |
| `default_token_ttl` | `UZAIR_DEFAULT_TOKEN_TTL` | `3600` | Fallback TTL токена (сек), если провайдер не вернул `expires_in` |
| `login_route` | `UZAIR_LOGIN_ROUTE` | `login` | Имя маршрута повторной аутентификации |
| `redirect_to` | `UZAIR_REDIRECT_TO` | `dashboard` | Маршрут или URL перенаправления после входа |
| `redirect_on_error` | `UZAIR_REDIRECT_ON_ERROR` | `/` | Куда вернуть пользователя, если вход не удался |
| `redirect_after_logout` | `UZAIR_REDIRECT_AFTER_LOGOUT` | `/` | Куда вернуть пользователя после выхода |
| `single_session` | `UZAIR_SINGLE_SESSION` | `false` | Завершать ли остальные входы аккаунта при новом входе |
| `link_by_email` | `UZAIR_LINK_BY_EMAIL` | `false` | Связывать ли старые локальные аккаунты по email |
| `routes.prefix` | `UZAIR_ROUTE_PREFIX` | `auth` | Префикс маршрутов пакета |
| `routes.throttle` | `UZAIR_ROUTE_THROTTLE` | `60,1` | Лимит запросов на SSO-эндпоинты (`попыток,минут`), на браузер |
| `routes.ip_throttle` | `UZAIR_ROUTE_IP_THROTTLE` | `120,1` | Потолок запросов на адрес (`попыток,минут`) для защиты от ротации cookie |
| `timeout` | `UZAIR_TIMEOUT` | `10` | Таймаут HTTP-запросов к SSO (сек) |
| `connect_timeout` | `UZAIR_CONNECT_TIMEOUT` | `5` | Таймаут соединения с SSO (сек) |
| `revocation_timeout` | `UZAIR_REVOCATION_TIMEOUT` | `3` | Таймаут запросов отзыва токенов (сек) |
| `revocation_concurrency` | `UZAIR_REVOCATION_CONCURRENCY` | `10` | Сколько грантов отзывается у SSO одновременно; `1` — по одному |
| `login_cache_ttl` | `UZAIR_LOGIN_CACHE_TTL` | `0` | Сколько секунд `uzair.token` может пропускать запрос по уже найденному входу, не читая строку; `0` — читать всегда |
| `login_cache_store` | `UZAIR_LOGIN_CACHE_STORE` | — | Имя хранилища кеша для кеширования входов (по умолчанию — системный кеш) |
| `lock_store` | `UZAIR_LOCK_STORE` | — | Хранилище кеша для atomic lock при обновлении токена |

> Для получения доступа к UzAirports ID, пожалуйста, свяжитесь с технической поддержкой: it@uzairports.com

## PKCE

По умолчанию пакет отправляет `code_challenge`/`code_challenge_method=S256`: код авторизации
привязывается к одноразовому verifier в сессии, поэтому перехваченный код никто, кроме
запросившего его браузера, обменять не сможет. Если ваш экземпляр UzAirports ID отвергает
`code_challenge`, отключите PKCE через `UZAIR_PKCE=false`.

---

Далее: [Идентификация пользователя](user-identification.md)
