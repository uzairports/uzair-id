## UzAirports ID для Laravel

OAuth 2.0 интеграция с системой единой аутентификации [Uzbekistan Airports](https://my.uzairports.com).  
Позволяет авторизовать пользователей через UzAirports ID, автоматически создавать аккаунты, управлять токенами и выполнять безопасный logout.

### Установка

```bash
composer require uzairports/uzair-id
```
Опубликуйте конфигурацию и миграции:
```bash
php artisan vendor:publish --provider=Uzairports\Uzairid\Providers\UzairServiceProvider
```
```bash
php artisan migrate
```

Публикуются четыре миграции: они приводят таблицу `users` к виду, пригодному для SSO
(добавляют `uzair_id`, убирают `password` и ограничения с `email`), и создают таблицу
`oauth_tokens`. Все изменения `users` идемпотентны — если колонка уже есть или ограничение
уже снято, шаг пропускается, поэтому миграции безопасно публиковать в существующее приложение.

### Конфигурация

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
| `refresh_leeway` | `UZAIR_REFRESH_LEEWAY` | `60` | За сколько секунд до истечения обновлять токен |
| `login_route` | `UZAIR_LOGIN_ROUTE` | `login` | Имя маршрута повторной аутентификации |

> Для получения доступа к UzAirports ID, пожалуйста, свяжитесь с технической поддержкой: it@uzairports.com

### Идентификация пользователя

Пользователя опознаёт только `id`, выданный UzAirports ID, — он хранится в `users.uzair_id`.
Имя и почту владелец аккаунта может поменять в любой момент на стороне SSO, почта может
повторяться у разных аккаунтов и может вовсе отсутствовать, поэтому искать пользователя
по `email` нельзя: смена почты создаст дубль, а совпадение почты отдаст чужой аккаунт.
Именно поэтому миграции снимают с `email` уникальность и `NOT NULL`.

Сопоставление выполняет `ResolveUserFromSocialite`: он находит аккаунт по `uzair_id`,
обновляет имя и почту данными от SSO и создаёт запись, если её ещё нет. Аккаунты, заведённые
до установки пакета, один раз привязываются по совпадению почты — но только те, у которых
`uzair_id` ещё пуст, чтобы чужую учётку нельзя было забрать сменой почты в SSO.

Модель пользователя берётся из `auth.providers.users.model`, поля пишутся через `forceFill()`,
так что перечислять их в `$fillable` не требуется.

### Аутентификация

#### Маршруты
Добавьте в routes/web.php:

```php
Route::get('/auth/redirect', [App\Http\Controllers\OAuthController::class, 'redirect'])->name('login');
Route::get('/auth/callback', [App\Http\Controllers\OAuthController::class, 'callback'])->name('callback');
Route::post('/auth/logout', [App\Http\Controllers\OAuthController::class, 'logout'])->name('logout');
```

Имя маршрута аутентификации должно совпадать с `uzairports.login_route` — на него пакет
возвращает пользователя, когда сессию больше нельзя продлить.

#### Контроллер
Создайте OAuthController.php:

```php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as SocialiteUser;
use Uzairports\Uzairid\Actions\ResolveUserFromSocialite;

class OAuthController extends Controller
{
    public function redirect()
    {
        return Socialite::driver('uzairports')->redirect();
    }

    public function callback(Request $request, ResolveUserFromSocialite $resolveUser)
    {
        try {
            $uzairUser = Socialite::driver('uzairports')->user();

            $user = DB::transaction(function () use ($uzairUser, $resolveUser): User {
                /** @var User $user */
                $user = $resolveUser($uzairUser);

                $user->token()->updateOrCreate(
                    [
                        'user_id' => $user->id,
                    ],
                    [
                        'access_token' => $uzairUser->token,
                        'refresh_token' => $uzairUser->refreshToken,
                        'expires_at' => $this->expiresAt($uzairUser),
                    ]
                );

                return $user;
            });
        } catch (\Throwable $e) {
            return redirect('/');
        }

        auth()->login($user);

        $request->session()->regenerate();

        return redirect()->intended('/dashboard');
    }

    public function logout(Request $request)
    {
        if (auth()->check()) {
            $user = auth()->user();

            if ($user->token) {
                try {
                    Socialite::driver('uzairports')->logout($user->token->access_token);
                } catch (\Throwable $e) {
                    // Недоступность SSO не должна мешать выйти локально.
                }

                $user->token()->delete();
            }

            Auth::logout();
        }

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return $request->wantsJson()
            ? new JsonResponse([], 204)
            : redirect('/');
    }

    private function expiresAt(SocialiteUser $uzairUser): ?Carbon
    {
        return $uzairUser->expiresIn === null
            ? null
            : now()->addSeconds((int) $uzairUser->expiresIn);
    }
}
```

Пользователь и его токен пишутся в одной транзакции **до** `auth()->login()`: сессия рядом с
недописанным токеном оставила бы пользователя авторизованным, но без возможности обратиться
к SSO. Провайдер не обязан возвращать `refresh_token` и время жизни — колонки допускают
`null`, а неизвестный срок хранится как `null` и трактуется как истёкший.
#### Модель пользователя
Добавьте в User.php:

```php
    public function token()
    {
        return $this->hasOne(OauthToken::class);
    }
```

### Обновление токена

Access token живёт ограниченное время. Пакет хранит момент истечения в колонке `expires_at`
и умеет обменивать `refresh_token` на новый access token через middleware `uzair.token`:

```php
Route::get('/dashboard', [DashboardController::class, 'index'])
    ->middleware(['auth', 'uzair.token']);
```

Middleware обновляет токен, если тот истекает в ближайшие `uzairports.refresh_leeway`
секунд (по умолчанию 60, настраивается через `UZAIR_REFRESH_LEEWAY`). Если SSO отказывается
обменивать refresh token, токен удаляется, сессия сбрасывается и поднимается
`AuthenticationException` — браузер уезжает на маршрут из `uzairports.login_route` с
сохранением исходного адреса, а запрос с `Accept: application/json` получает `401`.

UzAirports ID ротирует refresh token, поэтому потратить его можно только один раз: два
параллельных запроса, обменивающих один и тот же токен, оставили бы проигравшего с уже
аннулированным. Обмен идёт под блокировкой (`Cache::lock`), и тот, кто её дождался, читает
токен, сохранённый победителем, вместо повторного обмена. Блокировку держит кеш, поэтому в
продакшене он должен быть общим для всех процессов приложения (`database`, `redis`,
`memcached`, `file`): `array` живёт внутри одного процесса и запросы между собой не разведёт.

Токен можно обновить и вручную:

```php
use Uzairports\Uzairid\Actions\RefreshAccessToken;

$refreshed = app(RefreshAccessToken::class)($user->token);
```

## Лицензия

Этот пакет распространяется под лицензией MIT.

Copyright (c) 2025 JSC "Uzbekistan Airports"

См. файл [LICENSE](./LICENSE.md) для подробностей.
