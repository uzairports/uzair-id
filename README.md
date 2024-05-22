## Пакет Uzbekistan airports

### Установка

```sh
composer require uzairports/uzair-id
```
```sh
php artisan migrate
```

### Конфигурация

Добавить config/services.php

```php
'uzairports' => [
    'client_id' => env('UZAIR_CLIENT_ID'),
    'client_secret' => env('UZAIR_CLIENT_SECRET'),
    'redirect' => env('UZAIR_CALLBACK_URL'),
],
```

### Аутентификация

Добавить маршруты

```php
Route::get('/auth/redirect', [App\Http\Controllers\OAuthController::class, 'redirect'])->name('uzair.redirect');
Route::get('/auth/callback', [App\Http\Controllers\OAuthController::class, 'callback'])->name('uzair.callback');
Route::post('/auth/logout', [App\Http\Controllers\OAuthController::class, 'logout'])->name('uzair.logout');
```
В OAuthController.php

```php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;

class OAuthController extends Controller
{
    public function redirect()
    {
        return Socialite::driver('uzairports')->redirect();
    }

    public function callback()
    {
        $uzairUser = Socialite::driver('uzairports')->user();

        $user = User::query()
            ->firstOrCreate(
              ['email' => $uzairUser->getEmail()],
              [
                  'email' => $uzairUser->getEmail(),
                  'name' => $uzairUser->getName(),
              ]
            );

        auth()->login($user);

        return to_route('dashboard');
    }

    public function logout(Request $request)
    {
        Auth::logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return $request->wantsJson()
            ? new JsonResponse([], 204)
            : redirect('/');
    }
}
```
