## UzAirports ID для Laravel

OAuth 2.0 интеграция с системой единой аутентификации [Uzbekistan Airports](https://my.uzairports.com).  
Позволяет авторизовать пользователей через UzAirports ID, автоматически создавать аккаунты, управлять токенами и выполнять безопасный logout.

### Быстрый старт

```bash
composer require uzairports/uzair-id

php artisan vendor:publish --tag=uzairid-config
php artisan vendor:publish --tag=uzairid-migrations
php artisan migrate
```

```env
UZAIR_CLIENT_ID=your-client-id
UZAIR_CLIENT_SECRET=your-client-secret
UZAIR_CALLBACK_URL=https://your-app.com/auth/callback
```

Маршруты — в `routes/web.php`:

```php
use Uzairports\Uzairid\Uzair;

Uzair::routes();
```

Трейт — в модели `User`:

```php
use Uzairports\Uzairid\Concerns\HasUzairToken;

class User extends Authenticatable
{
    use HasUzairToken;
}
```

Middleware `uzair.token` — на **все** аутентифицированные маршруты: он обновляет access-токен,
замечает завершённые входы и продлевает строку входа, чтобы уборка не удалила её из-под
живого пользователя.

```php
Route::get('/dashboard', [DashboardController::class, 'index'])
    ->middleware(['auth', 'uzair.token']);
```

> ⚠️ Перед установкой в приложение с существующей таблицей `users` прочитайте раздел
> [Установка](docs/installation.md): пакету нужно, чтобы с `users.email` были сняты
> уникальность и `NOT NULL`, а колонка `password` — удалена либо `nullable`.

### Документация

| Раздел | О чём |
| --- | --- |
| [Установка](docs/installation.md) | Composer, публикация конфигурации, базовые и опциональные миграции, обновление со старых версий, языковые файлы |
| [Конфигурация](docs/configuration.md) | Переменные `.env`, полная таблица ключей `config/uzairports.php`, PKCE |
| [Идентификация пользователя](docs/user-identification.md) | Почему опознание идёт по `uzair_id`, `ResolveUserFromSocialite`, привязка старых аккаунтов по email |
| [Аутентификация](docs/authentication.md) | Маршруты и лимиты, конфликт имени `login`, контроллер, трейт `HasUzairToken` |
| [Сессии и устройства](docs/sessions.md) | Несколько устройств, смена id сессии, гибридный вход по паролю, завершение входов, список входов, уборка, единственная сессия |
| [События](docs/events.md) | Четыре доменных события и пример регистрации слушателей |
| [Обновление токена](docs/token-refresh.md) | Middleware `uzair.token`, блокировка при параллельных запросах, ручное обновление |

История изменений — в [CHANGELOG.md](./CHANGELOG.md).

> Для получения доступа к UzAirports ID, пожалуйста, свяжитесь с технической поддержкой: it@uzairports.com

### Тесты и статический анализ

```bash
composer test
composer analyse
```

## Лицензия

Этот пакет распространяется под лицензией MIT.

Copyright (c) 2025 JSC "Uzbekistan Airports"

См. файл [LICENSE](./LICENSE.md) для подробностей.
