<?php

namespace App\Domain\Rbac\Services;

use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Models\UserRoleAssignment;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * What spatie/laravel-permission has no model for: modules.
 *
 * Permission CHECKS are Spatie's -- $user->can(), hasPermissionTo(), @can and
 * the permission: middleware -- made scope-aware by User::roles() and
 * User::hasPermissionTo(). This class supplies the one rule those call into:
 * a permission belongs to a module, and an account that has not enabled the
 * module is denied it, whoever is asking. Module enablement is a commercial
 * boundary, not a convenience.
 *
 * It also answers the two "anywhere" questions the UI asks -- every permission
 * a user holds, and the modules they should see -- which cross accounts and so
 * cannot go through Spatie's one-team-at-a-time relation.
 */
class PermissionCatalog
{
    private const CACHE_TTL = 300;

    /** Permission name => module key, memoised for the request. */
    private ?array $catalog = null;

    /**
     * Is this permission's module live -- and, when an account is in scope,
     * enabled for it? An unknown permission, or one whose module has been
     * switched off product-wide, is denied outright.
     */
    public function moduleAllows(string $permission, ?int $accountId): bool
    {
        $moduleKey = $this->catalog()[$permission] ?? null;

        if ($moduleKey === null) {
            return false;
        }

        return $accountId === null || $this->moduleEnabled($moduleKey, $accountId);
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
        if ($user->is_admin) {
            return array_keys($this->catalog());
        }

        return $this->grantedPermissions($user)->pluck('permission')
            ->unique()->sort()->values()->all();
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

        if ($user->is_admin) {
            return collect($enabled)->sort()->values()->all();
        }

        return $this->grantedPermissions($user)
            ->where('account_id', $accountId)
            ->pluck('module_key')
            ->unique()
            ->filter(fn ($key) => in_array($key, $enabled, true))
            ->sort()
            ->values()
            ->all();
    }

    /**
     * Every live grant flattened to permission + module + scope, across all
     * accounts. Deliberately bypasses Spatie's roles() relation: that filters
     * to one team, and these two callers are asking "anywhere".
     */
    private function grantedPermissions(User $user)
    {
        $now = now();
        $table = (new UserRoleAssignment)->getTable();

        return DB::table("{$table} as ura")
            ->join('roles as r', 'r.id', '=', 'ura.role_id')
            ->join('permission_role as pr', 'pr.role_id', '=', 'r.id')
            ->join('permissions as p', 'p.id', '=', 'pr.permission_id')
            ->join('modules as m', 'm.id', '=', 'p.module_id')
            ->where('ura.model_id', $user->id)
            ->where('ura.model_type', $user::class)
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
    }

    /** Permission name => module key, for every permission in an active module. */
    private function catalog(): array
    {
        return $this->catalog ??= Cache::remember('rbac:permission_catalog', self::CACHE_TTL,
            fn () => DB::table('permissions as p')
                ->join('modules as m', 'm.id', '=', 'p.module_id')
                ->whereNull('p.deleted_at')
                ->whereNull('m.deleted_at')
                ->where('m.is_active', true)
                ->pluck('m.key', 'p.name')
                ->all());
    }

    /** Call after toggling a module for an account. */
    public function flushModule(string $moduleKey, int $accountId): void
    {
        Cache::forget("rbac:module:{$accountId}:{$moduleKey}");
    }

    public function flushCatalog(): void
    {
        $this->catalog = null;
        Cache::forget('rbac:permission_catalog');
    }
}
