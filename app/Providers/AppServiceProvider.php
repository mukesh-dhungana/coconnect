<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     *
     * No Gate::before for permissions: spatie/laravel-permission registers its
     * own (config permission.register_permission_check_method), and it calls
     * User::hasPermissionTo(), which carries the module, super-admin, location
     * and validity rules. See App\Domain\Identity\Models\User.
     */
    public function boot(): void
    {
        //
    }
}
