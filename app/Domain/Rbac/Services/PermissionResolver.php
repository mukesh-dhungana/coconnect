<?php

namespace App\Domain\Rbac\Services;

use App\Domain\Identity\Models\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * Resolves whether a user holds a permission at a given scope.
 *
 * Deny by default. A permission is granted only if every one of these holds:
 *
 *   1. The user has an ACTIVE assignment of a role that carries the permission.
 *      Active = not revoked, started, not expired.
 *   2. That assignment's scope COVERS the scope being asked about:
 *        global   -> covers everything
 *        account  -> covers that account and its locations
 *        location -> covers that location only
 *   3. The permission's MODULE is enabled for the account being asked about.
 *      A disabled module denies even a System Administrator, because the
 *      client has not bought it.
 *
 * Rule 3 is the one people forget. Module enablement is a commercial boundary,
 * not a convenience, so it is enforced here rather than only hidden in the UI.
 */
class PermissionResolver
{
    private const CACHE_TTL = 300;

    /** Every active grant for a user, flattened to permission + scope. */
    public function grantsFor(User $user): array
    {
        return Cache::remember(
            $this->cacheKey($user->id),
            self::CACHE_TTL,
            fn () => $this->loadGrants($user->id)
        );
    }

    private function loadGrants(int $userId): array
    {
        $now = now();

        $rows = DB::table('user_role_assignments as ura')
            ->join('roles as r', 'r.id', '=', 'ura.role_id')
            ->join('permission_role as pr', 'pr.role_id', '=', 'r.id')
            ->join('permissions as p', 'p.id', '=', 'pr.permission_id')
            ->join('modules as m', 'm.id', '=', 'p.module_id')
            ->where('ura.user_id', $userId)
            ->whereNull('ura.revoked_at')
            ->whereNull('r.deleted_at')
            ->whereNull('p.deleted_at')
            ->where('m.is_active', true)
            ->where(fn ($q) => $q->whereNull('ura.valid_from')->orWhere('ura.valid_from', '<=', $now))
            ->where(fn ($q) => $q->whereNull('ura.valid_until')->orWhere('ura.valid_until', '>', $now))
            ->select([
                'p.name as permission',
                'm.key as module_key',
                'ura.scope_level',
                'ura.account_id',
                'ura.location_id',
                'r.name as role_name',
            ])
            ->get();

        return $rows->map(fn ($r) => (array) $r)->all();
    }

    /**
     * @param  string    $permission  e.g. 'roster.publish'
     * @param  int|null  $accountId   the account being acted on
     * @param  int|null  $locationId  the location being acted on
     */
    public function allows(User $user, string $permission, ?int $accountId = null, ?int $locationId = null): bool
    {
        foreach ($this->grantsFor($user) as $grant) {
            if ($grant['permission'] !== $permission) {
                continue;
            }

            if (! $this->scopeCovers($grant, $accountId, $locationId)) {
                continue;
            }

            // The module must be enabled for the account in question. A global
            // grant acting on a specific account is still bound by that account's
            // module list.
            $moduleAccount = $accountId ?? $grant['account_id'];

            if ($moduleAccount !== null && ! $this->moduleEnabled($grant['module_key'], (int) $moduleAccount)) {
                continue;
            }

            return true;
        }

        return false;
    }

    /** Does a grant's scope cover the scope being asked about? */
    private function scopeCovers(array $grant, ?int $accountId, ?int $locationId): bool
    {
        return match ($grant['scope_level']) {
            'global'  => true,
            'account' => $accountId !== null && (int) $grant['account_id'] === $accountId,
            'location' => $locationId !== null
                && (int) $grant['location_id'] === $locationId
                && ($accountId === null || (int) $grant['account_id'] === $accountId),
            default => false,
        };
    }

    public function moduleEnabled(string $moduleKey, int $accountId): bool
    {
        return Cache::remember(
            "rbac:module:{$accountId}:{$moduleKey}",
            self::CACHE_TTL,
            fn () => DB::table('account_module as am')
                ->join('modules as m', 'm.id', '=', 'am.module_id')
                ->where('am.account_id', $accountId)
                ->where('m.key', $moduleKey)
                ->where('am.is_enabled', true)
                ->where('m.is_active', true)
                ->exists()
        );
    }

    /** Distinct permission names the user holds anywhere -- for UI hints only. */
    public function permissionNames(User $user): array
    {
        return collect($this->grantsFor($user))->pluck('permission')->unique()->sort()->values()->all();
    }

    /** Which modules should appear in this user's navigation for an account. */
    public function visibleModules(User $user, int $accountId): array
    {
        $enabled = DB::table('account_module as am')
            ->join('modules as m', 'm.id', '=', 'am.module_id')
            ->where('am.account_id', $accountId)
            ->where('am.is_enabled', true)
            ->where('m.is_active', true)
            ->pluck('m.key')
            ->all();

        return collect($this->grantsFor($user))
            ->filter(fn ($g) => in_array($g['module_key'], $enabled, true))
            ->filter(fn ($g) => $g['scope_level'] === 'global' || (int) $g['account_id'] === $accountId)
            ->pluck('module_key')
            ->unique()
            ->sort()
            ->values()
            ->all();
    }

    public function flush(int $userId): void
    {
        Cache::forget($this->cacheKey($userId));
    }

    private function cacheKey(int $userId): string
    {
        return "rbac:grants:{$userId}";
    }
}
