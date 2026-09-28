<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

/*
|--------------------------------------------------------------------------
| Scheduled tasks
|--------------------------------------------------------------------------
|
| These run only if every environment calls the scheduler once a minute:
|
|   * * * * * cd /path/to/backend && php artisan schedule:run >> /dev/null 2>&1
|
| Locally, run `php artisan schedule:work` instead. Nothing errors when the
| scheduler is missing -- the tasks just never run -- so check it on each
| environment (`php artisan schedule:list` shows what is registered).
|
| onOneServer() needs a cache store with locks (database or redis, not file).
*/

// Audit entries for temporary grants that have run out. Access itself already
// ends at valid_until; this only makes the expiry visible in the audit log.
Schedule::command('rbac:record-expiries')
    ->everyFiveMinutes()
    ->withoutOverlapping()
    ->onOneServer();
