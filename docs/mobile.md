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

Приложение само проверяет `state`. `code_verifier` обязателен всегда, независимо от
браузерного `pkce`: без него перехваченный код смог бы обменять кто угодно.

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
| `POST` | `/api/auth/token` | `uzair.api.token` | `200 {token, token_type, expires_at}`, `422` при неверных полях, `401` при отказе авторизации, `503` при сбое провайдера или сервера |
| `POST` | `/api/auth/refresh` | `uzair.api.refresh` | `200 {token, token_type, expires_at}` — новый токен Sanctum взамен присланного, `401` если вход завершён или его больше нечем продлить, `409 {"error":"token_rotated"}` если тот же токен только что обменял параллельный `refresh`, `503` при сбое провайдера или сервера |
| `POST` | `/api/auth/logout` | `uzair.api.logout` | `204` — завершает вход этого устройства |
| `POST` | `/api/auth/logout-device/{token}` | `uzair.api.logoutDevice` | `204` — завершает один вход аккаунта по `id` строки |

`refresh` вызывается с текущим токеном в заголовке `Authorization: Bearer …`. Если грант
SSO истекает в пределах `refresh_leeway`, пакет сначала обновляет его, а затем выпускает
новый токен Sanctum. Старый токен при этом удаляется, поэтому клиент должен сразу заменить
его тем, что пришёл в ответе. Необязательное поле `device_name` задаёт имя нового токена.
Без него имя угадывается по user-agent входа.

Если сохранение нового токена, его связи со входом или удаление старого токена не удалось, ротация откатывается:
старый токен остаётся, сервер отвечает `503`, и клиент может повторить `refresh`.

Два `refresh` с одним и тем же токеном разводятся блокировкой строки входа: первый выпускает
новый токен и удаляет старый, второй, дождавшись блокировки, видит, что вход уже переведён на
другой токен, и отвечает `409` с телом `{"error": "token_rotated", "message": "…"}`.
**Это не выход из аккаунта:** вход жив под токеном, который получил первый запрос, — клиенту
нужно взять его и не повторять `refresh` со старым. `401` по-прежнему означает, что вход
завершён. Запрос, пришедший уже после того, как первый удалил старый токен, Sanctum не
аутентифицирует, и он получает `401`. Так же `401` получит и запрос, который Sanctum успел
аутентифицировать, но строку входа прочитал уже после того, как первый запрос зафиксировал
ротацию: старого токена к этому моменту нет, и отличить такой вход от завершённого серверу нечем.
Поэтому `409` — подсказка, а не гарантия: **сериализуйте `refresh` на клиенте**.

`expires_at` в ответах `token` и `refresh` учитывает оба ограничения: срок конкретного
токена (`uzairports.api.token_expiration`) и общий срок Sanctum (`sanctum.expiration`).
Если заданы оба, возвращается более ранний момент истечения; если ни один — `null`.

Отправляйте `Accept: application/json` — так ошибки валидации приходят как JSON. Маршруты
стоят за тем же лимитером `uzairid`, что и браузерные. Параметры `Uzair::apiRoutes()` те же,
что у `Uzair::routes()`: `prefix`, `throttle`, `middleware`, `controller`.

## Что происходит с токеном Sanctum

- `uzair.token` ищет вход по токену запроса, поэтому два телефона одного аккаунта не делят
  один грант.
- Завершение входа любым путём — выход, `logoutDevice` из браузера, `single_session`,
  уборка — удаляет и токен Sanctum. Иначе приложение продолжало бы проходить маршруты без
  `uzair.token`.
- Если токен Sanctum истёк по своему `expires_at` или общему `sanctum.expiration`,
  `uzair:prune` удалит и токен, и строку входа и отдаст её гранты SSO. Предварительный
  запуск `sanctum:prune-expired` для этого не нужен.
- Если токен Sanctum удалён в обход пакета (`sanctum:prune-expired`,
  `$user->tokens()->delete()`), строку входа также заберёт `uzair:prune` и отдаст её гранты SSO.

Токены Sanctum, которые приложение выдаёт само (например, вход по паролю), строки
`oauth_tokens` не имеют. Для них остаётся правило `Uzair::treatRequestsAsLocalWhen()` — см.
[Запрос без сессии](sessions.md#запрос-без-сессии-sanctum-и-api).

---

Далее: [События](events.md)
