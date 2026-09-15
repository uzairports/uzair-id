<?php

namespace Uzairports\Uzairid\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Str;
use RuntimeException;
use Throwable;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\EnsureTokenStorageMatchesProvider;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Uzair;

class ProviderCommand extends Command
{
    protected $signature = 'uzair:provider
        {--end-sessions : End all SSO logins under the current provider before changing configuration}
        {--rebuild-empty : Back up and recreate an empty token table for the newly configured provider}';

    protected $description = 'Check the token owner and prepare a controlled change of account provider';

    public function handle(EnsureTokenStorageMatchesProvider $check, EndSessions $endSessions): int
    {
        try {
            if ($this->option('end-sessions') && $this->option('rebuild-empty')) {
                throw new RuntimeException('Run the two transition stages separately, changing provider configuration between them.');
            }

            if ($this->option('end-sessions') || $this->option('rebuild-empty')) {
                if (! app()->isDownForMaintenance()) {
                    throw new RuntimeException('Enable maintenance mode and stop background writers before changing the token owner.');
                }

                if ($this->option('rebuild-empty')) {
                    $this->rebuildEmptyTable();

                    return self::SUCCESS;
                }

                $check();
                OauthToken::query()->chunkById(100, function (Collection $tokens) use ($endSessions): void {
                    $endSessions->endAll($tokens);
                });

                if (OauthToken::query()->exists()) {
                    throw new RuntimeException('Some token rows could not be deleted. Keep the old provider configured and resolve the deletion failures.');
                }

                $this->info('SSO logins ended locally; remote revocation was attempted. Check revocation warnings before continuing.');

                return self::SUCCESS;
            }

            $problem = $check->problem();
            if ($problem === null) {
                $this->info('The token table matches the configured account provider.');

                return self::SUCCESS;
            }

            $this->error($problem);
        } catch (Throwable $exception) {
            $this->error($exception->getMessage());
        }

        $this->line('Transition: enable maintenance and stop writers; restore the old provider; run uzair:provider --end-sessions; configure the new provider and refresh cached configuration; run uzair:provider --rebuild-empty; run uzair:provider before resuming traffic.');

        return self::FAILURE;
    }

    private function rebuildEmptyTable(): void
    {
        $model = Uzair::userModel();
        $user = new $model;
        $token = new OauthToken;
        $connection = $token->getConnection();
        $schema = $connection->getSchemaBuilder();
        $table = $token->getTable();

        if ($user->getConnection()->getName() !== $connection->getName()
            || ! $schema->hasColumn($user->getTable(), $user->getKeyName())
            || ! $schema->hasColumn($user->getTable(), 'uzair_id')) {
            throw new RuntimeException('Prepare the target account table, its key and uzair_id on the token database connection first.');
        }

        if ($this->tokenRowsExist()) {
            throw new RuntimeException('The token table is not empty. End its logins under the old provider first; ids will not be reassigned.');
        }

        foreach ($schema->getTables() as $existing) {
            foreach ($schema->getForeignKeys($existing['schema_qualified_name']) as $key) {
                if ($key['foreign_table'] === $connection->getTablePrefix().$table) {
                    throw new RuntimeException('Another table references oauth_tokens. Prepare an application-specific migration preserving that reference.');
                }
            }
        }

        $migration = require __DIR__.'/../../../database/migrations/create_oauth_tokens_table.php';
        $create = [$migration, 'up'];
        if (! is_callable($create) || ! is_object($migration) || ! property_exists($migration, 'table')) {
            throw new RuntimeException('The token table migration cannot be run.');
        }

        $suffix = Str::lower(Str::random(12));
        $backup = 'uzair_tokens_backup_'.$suffix;
        $staged = 'uzair_tokens_next_'.$suffix;
        $migration->table = $staged;
        $create();

        if ($this->tokenRowsExist()) {
            $schema->drop($staged);
            throw new RuntimeException('A writer added tokens during preparation. Stop all writers and retry under the old provider.');
        }

        $schema->rename($table, $backup);

        try {
            $schema->rename($staged, $table);
        } catch (Throwable $exception) {
            if (! $schema->hasTable($table)) {
                $schema->rename($backup, $table);
            }

            throw $exception;
        }

        $this->info("Token table recreated. The previous empty table is preserved as [{$backup}].");
    }

    /** @phpstan-impure */
    private function tokenRowsExist(): bool
    {
        return OauthToken::query()->exists();
    }
}
