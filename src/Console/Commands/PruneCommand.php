<?php

namespace Uzairports\Uzairid\Console\Commands;

use Illuminate\Console\Command;
use Uzairports\Uzairid\Models\OauthToken;

class PruneCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'uzair:prune
                            {--pretend : Display the number of prunable tokens without deleting them}
                            {--chunk= : The number of models to retrieve per chunk}
                            {--no-revoke : Skip remote grant revocation at the identity provider}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Prune abandoned UzAirports ID tokens whose sessions have expired';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $parameters = ['--model' => [OauthToken::class]];

        if ($this->option('pretend')) {
            $parameters['--pretend'] = true;
        }

        if ($this->option('chunk')) {
            $parameters['--chunk'] = (int) $this->option('chunk');
        }

        if ($this->option('no-revoke')) {
            config(['uzairports.revoke_on_prune' => false]);
        }

        return $this->call('model:prune', $parameters);
    }
}
