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
    protected $signature = 'uzair:prune {--pretend : Display the number of prunable tokens without deleting them}';

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

        return $this->call('model:prune', $parameters);
    }
}
