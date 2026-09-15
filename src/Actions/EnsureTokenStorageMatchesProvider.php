<?php

namespace Uzairports\Uzairid\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Log;
use RuntimeException;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Uzair;

class EnsureTokenStorageMatchesProvider
{
    public function forUser(Authenticatable $user): void
    {
        $this();

        if (! Uzair::accountMatchesProvider($user)) {
            throw new ServiceUnavailableHttpException(null, 'The route account does not belong to the UzAirports provider.');
        }
    }

    public function __invoke(): void
    {
        try {
            $problem = $this->problem();
        } catch (RuntimeException $exception) {
            $problem = $exception->getMessage();
        }

        if ($problem === null) {
            return;
        }

        Log::error($problem);

        throw new ServiceUnavailableHttpException(null, $problem);
    }

    /**
     * The existing foreign key is the evidence of which accounts own these ids.
     * Never reinterpret existing rows after a guard or model configuration change.
     */
    public function problem(): ?string
    {
        $model = Uzair::userModel();
        $user = new $model;
        $token = new OauthToken;
        $connection = $token->getConnection();
        $schema = $connection->getSchemaBuilder();

        if ($user->getConnection()->getName() !== $connection->getName()) {
            return 'The UzAirports account and token models must use the same database connection.';
        }

        if (! $schema->hasTable($token->getTable())) {
            return 'The UzAirports token table is missing. Publish and run the package migrations.';
        }

        [$expectedSchema, $expectedTable] = $schema->parseSchemaAndTable($user->getTable(), withDefaultSchema: true);
        $expected = $connection->getTablePrefix().$expectedTable;

        foreach ($schema->getForeignKeys($token->getTable()) as $key) {
            if ($key['columns'] !== ['user_id']) {
                continue;
            }

            if ($key['foreign_schema'] === $expectedSchema && $key['foreign_table'] === $expected
                && $key['foreign_columns'] === [$user->getKeyName()]) {
                return null;
            }

            return "The UzAirports token owner is [{$key['foreign_table']}], but the configured provider uses [{$expected}]. Run php artisan uzair:provider for the transition procedure.";
        }

        return 'The UzAirports token owner cannot be verified without a user_id foreign key. Run php artisan uzair:provider.';
    }
}
