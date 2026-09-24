<?php

namespace App\Http\Middleware;

use App\Domain\Identity\Models\Account;
use App\Domain\Rbac\Support\PermissionScope;
use App\Support\Http\ApiResponse;
use App\Support\Tenancy\TenantContext;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Resolves which account this request acts inside, and proves the caller is
 * allowed into it.
 *
 * Order of preference:
 *   1. an {account} route parameter
 *   2. ?account_id= / X-Account-Id header
 *   3. the caller's only account, when they have exactly one
 *
 * A super administrator sees every account; anyone else must hold a grant in
 * the one they asked for.
 *
 * It also sets the PermissionScope -- Spatie's team plus the location -- that
 * every later check in the request answers for, so $user->can() and Spatie's
 * permission: middleware need no arguments. Location comes from a {location}
 * route parameter, ?location_id= or X-Location-Id. It is not validated
 * against the account here: a location from elsewhere matches no location
 * grant (GrantRole refuses those), so it can only narrow, never widen. Resolution and authorisation live together on purpose —
 * setting the tenant without checking access would be worse than not scoping
 * at all, because it would look safe.
 */
class ResolveTenant
{
    public function __construct(private TenantContext $tenant, private PermissionScope $scope) {}

    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        // Spatie's team is static state and outlives the request under Octane
        // or in tests. Start every request from nothing.
        $this->scope->set(null);

        if (! $user) {
            return $next($request);   // auth middleware will deal with it
        }

        $accountId = $this->requestedAccountId($request, $user);

        if ($accountId === null) {
            return $next($request);   // genuinely account-less endpoint
        }

        $account = Account::withoutGlobalScope('tenant')->find($accountId);

        if (! $account) {
            return ApiResponse::error('Account not found.', 404);
        }

        if (! $this->mayEnter($user, $account->id)) {
            return ApiResponse::error('You do not have access to this account.', 403);
        }

        $this->tenant->set($account);
        $this->scope->set($account->id, $this->requestedLocationId($request));

        return $next($request);
    }

    private function requestedAccountId(Request $request, $user): ?int
    {
        $param = $request->route('account');

        if ($param) {
            return (int) (is_object($param) ? $param->id : $param);
        }

        $explicit = $request->integer('account_id') ?: $request->header('X-Account-Id');

        if ($explicit) {
            return (int) $explicit;
        }

        $own = $this->accountIds($user);

        return count($own) === 1 ? $own[0] : null;
    }

    private function requestedLocationId(Request $request): ?int
    {
        $param = $request->route('location');

        if ($param) {
            return (int) (is_object($param) ? $param->id : $param);
        }

        $explicit = $request->integer('location_id') ?: $request->header('X-Location-Id');

        return $explicit ? (int) $explicit : null;
    }

    /** Accounts the caller holds any active grant in. */
    private function accountIds($user): array
    {
        return $user->roleAssignments()->active()
            ->whereNotNull('account_id')
            ->distinct()->pluck('account_id')
            ->map(fn ($id) => (int) $id)->all();
    }

    private function mayEnter($user, int $accountId): bool
    {
        // is_admin is the global scope level. It carries no assignment rows, so
        // there is nothing in accountIds() to find -- it has to be asked directly.
        return $user->is_admin || in_array($accountId, $this->accountIds($user), true);
    }
}
