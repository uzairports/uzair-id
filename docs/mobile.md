# Мобильное приложение (Sanctum)

[← Оглавление](README.md)

Браузер и SPA на том же домене входят через сессию — маршруты `Uzair::routes()` и cookie.
Мобильному приложению сессия недоступна, поэтому оно получает токен Sanctum, а его вход в
`oauth_tokens` записывается под этим токеном так же, как вход браузера записан под сессией.
Оба способа работают одновременно.

## Как проходит вход

```
App ── authorize (PKCE, тот же client_id) ──> UzAirports ID ── code ──> App
App ── POST /api/auth/token {code, code_verifier, redirect_uri, device_name} ──> Backend
       обмен кода с client_secret → грант SSO, аккаунт, токен Sanctum, строка oauth_tokens
   <── {"token": "1|…", "token_type": "Bearer", "expires_at": "…"|null}
```

Код обменивает сервер, а не приложение, поэтому refresh token остаётся у сервера и
`uzair.token` продолжает его ротировать.

Приложение само проверяет `state`. `code_verifier` обязателен, пока включён `pkce`: без него
перехваченный код смог бы обменять кто угодно.

## Подключение

```bash
composer require laravel/sanctum
php artisan install:api
php artisan vendor:publish --tag=uzairid-upgrade-migrations   # колонка personal_access_token_id
php artisan migrate
```

Модель пользователя подключает оба трейта. У обоих есть `tokens()`, поэтому за Sanctum
остаётся `tokens()` (на нём держится `createToken()`), а входы SSO читаются через
`uzairTokens()`:

```php
use Laravel\Sanctum\HasApiTokens;
use Uzairports\Uzairid\Concerns\HasUzairToken;

class User extends Authenticatable
{
    use HasApiTokens, HasUzairToken {
        HasApiTokens::tokens insteadof HasUzairToken;
    }
}
```

В `routes/api.php`:

```php
use Uzairports\Uzairid\Uzair;

Uzair::apiRoutes();

Route::middleware(['auth:sanctum', 'uzair.token:sanctum'])->group(function () {
    // маршруты приложения
});
```

В `.env` перечислите redirect URI приложения — каждый должен быть зарегистрирован для этого
`client_id` в UzAirports ID:

```env
UZAIR_API_REDIRECT_URIS=uzapp://auth/callback
```

Пока список пуст, любой обмен отклоняется.

## Маршруты

| Метод | URI | Имя | Ответ |
| --- | --- | --- | --- |
| `POST` | `/api/auth/token` | `uzair.api.token` | `200 {token, token_type, expires_at}`, `422` при неверных полях, `401` если вход не удался |
| `POST` | `/api/auth/logout` | `uzair.api.logout` | `204` — завершает вход этого устройства |
| `POST` | `/api/auth/logout-device/{token}` | `uzair.api.logoutDevice` | `204` — завершает один вход аккаунта по `id` строки |

Отправляйте `Accept: application/json` — так ошибки валидации приходят как JSON. Маршруты
стоят за тем же лимитером `uzairid`, что и браузерные. Параметры `Uzair::apiRoutes()` те же,
что у `Uzair::routes()`: `prefix`, `throttle`, `middleware`, `controller`.

## Что происходит с токеном Sanctum

- `uzair.token` ищет вход по токену запроса, поэтому два телефона одного аккаунта не делят
  один грант.
- Завершение входа любым путём — выход, `logoutDevice` из браузера, `single_session`,
  уборка — удаляет и токен Sanctum. Иначе приложение продолжало бы проходить маршруты без
  `uzair.token`.
- Если токен Sanctum удалён в обход пакета (истёк по `sanctum.expiration`,
  `sanctum:prune-expired`, `$user->tokens()->delete()`), строку входа заберёт `uzair:prune` и
  отдаст её грант SSO.

Токены Sanctum, которые приложение выдаёт само (например, вход по паролю), строки
`oauth_tokens` не имеют. Для них остаётся правило `Uzair::treatRequestsAsLocalWhen()` — см.
[Запрос без сессии](sessions.md#запрос-без-сессии-sanctum-и-api).

---

Далее: [События](events.md)
