<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Route guard: permission:<name>
 *
 * Resolves the account/location scope from the route, then defers to the
 * PermissionResolver. The resolver stays the single authority — this is
 * only a convenient place to call it.
 *
 *   Route::middleware('permission:roster.publish')
 *
 * Scope is taken from route parameters {account} / {location} when present,
 * then from ?account_id= / ?location_id=, and finally from the account
 * ResolveTenant put in the TenantContext for this request.
 */
use App\Support\Http\ApiResponse;
use App\Support\Tenancy\TenantContext;

class EnsurePermission
{
    public function __construct(private TenantContext $tenant) {}

    public function handle(Request $request, Closure $next, string $permission): Response
    {
        $user = $request->user();

        if (! $user) {
            return $this->deny($request, 'Unauthenticated.', 401);
        }

        [$accountId, $locationId] = $this->scopeFrom($request);

        if (! $user->hasPermission($permission, $accountId, $locationId)) {
            return $this->deny(
                $request,
                "You do not have permission to {$permission} in this scope.",
                403
            );
        }

        return $next($request);
    }

    /** @return array{0: int|null, 1: int|null} */
    private function scopeFrom(Request $request): array
    {
        $account = $request->route('account');
        $location = $request->route('location');

        $accountId = is_object($account) ? $account->id : ($account ?? $request->integer('account_id') ?: null);
        $locationId = is_object($location) ? $location->id : ($location ?? $request->integer('location_id') ?: null);

        // Nothing on the request said which account? Use the one ResolveTenant
        // already settled on. Without this the two middleware disagree: the
        // request is admitted into an account, then judged as if it had none,
        // and an account-scoped grant never covers a scope-less check.
        $accountId ??= $this->tenant->id();

        return [$accountId ? (int) $accountId : null, $locationId ? (int) $locationId : null];
    }

    private function deny(Request $request, string $message, int $status): Response
    {
        if ($request->expectsJson()) {
            return ApiResponse::error($message, $status);
        }

        abort($status, $message);
    }
}
