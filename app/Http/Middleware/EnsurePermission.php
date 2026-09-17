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
 * otherwise from ?account_id= / ?location_id= on the request.
 */
class EnsurePermission
{
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

        return [$accountId ? (int) $accountId : null, $locationId ? (int) $locationId : null];
    }

    private function deny(Request $request, string $message, int $status): Response
    {
        if ($request->expectsJson()) {
            return response()->json(['message' => $message], $status);
        }

        abort($status, $message);
    }
}
