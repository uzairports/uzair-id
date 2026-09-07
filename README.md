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

### Конфигурация

Добавьте настройки в config/services.php:

```php
'uzairports' => [
    'client_id' => env('UZAIR_CLIENT_ID'),
    'client_secret' => env('UZAIR_CLIENT_SECRET'),
    'redirect' => env('UZAIR_CALLBACK_URL'),
],
```
И в .env:
```env
UZAIR_CLIENT_ID=your-client-id
UZAIR_CLIENT_SECRET=your-client-secret
UZAIR_CALLBACK_URL=https://your-app.com/auth/callback
```
> Для получения доступа к UzAirports ID, пожалуйста, свяжитесь с технической поддержкой: it@uzairports.com

### Аутентификация

#### Маршруты
Добавьте в routes/web.php:

```php
Route::get('/auth/redirect', [App\Http\Controllers\OAuthController::class, 'redirect'])->name('login');
Route::get('/auth/callback', [App\Http\Controllers\OAuthController::class, 'callback'])->name('callback');
Route::post('/auth/logout', [App\Http\Controllers\OAuthController::class, 'logout'])->name('logout');
```
#### Контроллер
Создайте OAuthController.php:

```php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Laravel\Socialite\Facades\Socialite;

class OAuthController extends Controller
{
    public function redirect()
    {
        return Socialite::driver('uzairports')->redirect();
    }

    public function callback(Request $request)
    {
        try{
            $uzairUser = Socialite::driver('uzairports')->user();
        } catch(\Exception $e){
            return redirect('/');
        }

        $user = User::query()
            ->firstOrCreate(
              ['email' => $uzairUser->getEmail()],
              [
                  'email' => $uzairUser->getEmail(),
                  'name' => $uzairUser->getName(),
              ]
            );

        auth()->login($user);

        $request->session()->regenerate();

        $user->token()->updateOrCreate(
            ['user_id' => $user->id],
            [
                'access_token' => $uzairUser->token,
                'refresh_token' => $uzairUser->refreshToken,
                'expires_in' => $uzairUser->expiresIn,
                'expires_at' => now()->addSeconds((int) $uzairUser->expiresIn),
            ]
        );

        return redirect('/dashboard');
    }

    public function logout(Request $request)
    {
        if (auth()->check()) {
            $user = auth()->user();
            
            if ($user->token) {
                Socialite::driver('uzairports')->logout($user->token->access_token);
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
}
```
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
Route::get('/dashboard', [HomeController::class, 'index'])
    ->middleware(['auth', 'uzair.token']);
```

Middleware обновляет токен, если тот истекает в ближайшие `services.uzairports.refresh_leeway`
секунд (по умолчанию 60, настраивается через `UZAIR_REFRESH_LEEWAY`). Если SSO отказывается
обменивать refresh token, токен удаляется, сессия сбрасывается и пользователь отправляется
на маршрут `login` для повторной аутентификации.

Токен можно обновить и вручную:

```php
use Uzairports\Uzairid\Actions\RefreshAccessToken;

$refreshed = app(RefreshAccessToken::class)($user->token);
```

## Лицензия

Этот пакет распространяется под лицензией MIT.

Copyright (c) 2025 JSC "Uzbekistan Airports"

См. файл [LICENSE](./LICENSE.md) для подробностей.
