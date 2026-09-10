# События (Events)

[← Оглавление](README.md)

Пакет генерирует 4 доменных события жизненного цикла авторизации, на которые можно подписаться для аудита безопасности, синхронизации ролей и мониторинга:

## 1. `Uzairports\Uzairid\Events\UzairAuthenticated`

Вызывается сразу после успешного OAuth-входа и фиксации токена в БД (за пределами транзакции, поэтому связанная модель пользователя уже зафиксирована).

* **Свойства события:**
  * `$event->user` (`Illuminate\Database\Eloquent\Model`) — модель локального аутентифицированного пользователя.
  * `$event->socialiteUser` (`Laravel\Socialite\Two\User`) — объект профиля от провайдера UzAirports ID (включая `$socialiteUser->getId()`, `$socialiteUser->getEmail()`, `$socialiteUser->getName()` и сырые данные `$socialiteUser->getRaw()`).
  * `$event->token` (`?Uzairports\Uzairid\Models\OauthToken`) — сохраненная модель токена текущей сессии.

> **Слушателю с `ShouldQueue` гранты не достаются.** Событие сериализуется в payload очереди —
> строку в Redis, запись в `jobs`, след в упавшей задаче, — и `$socialiteUser` попадал туда
> целиком: и access-, и ротируемый refresh-токен открытым текстом, рядом с `$token`, ради
> которого пакет и держит `encrypted`-каст. В payload уходит копия профиля без них
> (`token` и `refreshToken` пустые), сам объект в текущем запросе не трогается, поэтому
> синхронный слушатель видит их как прежде. Очереди грант нужно читать из `$event->token` —
> `SerializesModels` пишет модель идентификатором, и токены возвращаются из строки через каст.

## 2. `Uzairports\Uzairid\Events\UzairLoggedOut`

Вызывается при завершении сеанса пользователя через маршрут `uzair.logout`.

* **Свойства события:**
  * `$event->user` (`?Illuminate\Database\Eloquent\Model`) — выходящий пользователь (или `null`, если сессия уже была сброшена).

## 3. `Uzairports\Uzairid\Events\UzairTokenRefreshed`

Вызывается при успешном фоновом или ручном обновлении access-токена через `RefreshAccessToken`.

* **Свойства события:**
  * `$event->token` (`Uzairports\Uzairid\Models\OauthToken`) — обновленная модель токена с новым `access_token`, `refresh_token` и `expires_at`.

## 4. `Uzairports\Uzairid\Events\UzairTokenRefreshFailed`

Вызывается при отказе сервера SSO обменять refresh-токен (например, токен отозван или устарел) либо при сбое соединения.

* **Свойства события:**
  * `$event->token` (`Uzairports\Uzairid\Models\OauthToken`) — токен, который не удалось обновить.
  * `$event->exception` (`?Throwable`) — исключение, возникшее при попытке обмена (если доступно).

## Пример регистрации слушателей (в `AppServiceProvider::boot()`)

```php
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Uzairports\Uzairid\Events\UzairAuthenticated;
use Uzairports\Uzairid\Events\UzairTokenRefreshFailed;

public function boot(): void
{
    // Аудит успешных входов и синхронизация дополнительных полей
    Event::listen(function (UzairAuthenticated $event): void {
        Log::info('User authenticated via UzAirports ID', [
            'user_id' => $event->user->getKey(),
            'uzair_id' => $event->socialiteUser->getId(),
            'device' => $event->token?->deviceLabel(),
        ]);
    });

    // Оповещение об ошибке ротации токена
    Event::listen(function (UzairTokenRefreshFailed $event): void {
        Log::warning('UzAirports token refresh failed', [
            'token_id' => $event->token->id,
            'user_id' => $event->token->user_id,
            'reason' => $event->exception?->getMessage(),
        ]);
    });
}
```

---

Далее: [Обновление токена](token-refresh.md)
