<?php

namespace App\Providers;

use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Services\PermissionResolver;
use Illuminate\Support\Facades\Gate;
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
     */
    public function boot(): void
    {
        $this->registerScopedPermissionGate();
    }

    /**
     * Route every dotted ability through the resolver.
     *
     *   $user->can('roster.publish', [$accountId, $locationId])
     *
     *   @can('roster.publish', [$accountId, $locationId])
     *   Route::middleware('permission:roster.publish')
     *
     * Why before() and not a policy or an after() hook:
     *
     *   - A POLICY is per model class. These abilities are not about a model,
     *     they are about a scope, so there is nothing to hang a policy on.
     *   - An AFTER hook cannot deny. Gate::callAfterCallbacks does
     *     `$result ??= $afterResult`, so it can only fill in a null result,
     *     never overturn a true. Module enablement has to be able to say no,
     *     so it must run inside the decision rather than after it.
     *
     * Abilities without a dot return null and fall through untouched, so
     * ordinary Laravel policies keep working exactly as they did.
     */
    private function registerScopedPermissionGate(): void
    {
        Gate::before(function (User $user, string $ability, array $arguments = []) {
            if (! str_contains($ability, '.')) {
                return null;
            }

            $accountId = $arguments['account'] ?? $arguments[0] ?? null;
            $locationId = $arguments['location'] ?? $arguments[1] ?? null;

            return app(PermissionResolver::class)->allows(
                $user,
                $ability,
                $accountId !== null ? (int) $accountId : null,
                $locationId !== null ? (int) $locationId : null,
            );
        });
    }
}
