<?php

namespace App\Domain\Rbac\Services;

use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Models\Role;
use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Support\Tenancy\TenantContext;
use Closure;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Spatie\Permission\PermissionRegistrar;

/**
 * Resolves whether a user holds a permission at a given scope.
 *
 * spatie/laravel-permission owns the part it is good at -- which permissions a
 * role carries, and the cache in front of that. This class owns the three
 * questions the package has no opinion on:
 *
 *   1. Is the user a SUPER ADMINISTRATOR? users.is_admin short-circuits
 *      everything. Spatie pins each assignment to one team, so "every account"
 *      is not something its tables can express; a flag is.
 *   2. Does the grant's LOCATION cover the location being asked about?
 *      Teams give one scope dimension and account_id has it, so location rides
 *      on the assignment pivot and is filtered in User::scopedRoles().
 *   3. Is the permission's MODULE enabled for the account being asked about?
 *
 * Rule 3 is the one people forget. Module enablement is a commercial boundary,
 * not a convenience, so it is enforced here rather than only hidden in the UI --
 * and it is checked BEFORE the super-admin flag, so a module the client has not
 * bought stays shut even for staff. That ordering is deliberate; moving the
 * is_admin check above it would quietly sell the module.
 *
 * Deny by default: every path that is not an explicit grant returns false.
 */
class PermissionResolver
{
    private const CACHE_TTL = 300;

    /** Permission name => module key, memoised for the request. */
    private ?array $catalog = null;

    public function __construct(private TenantContext $tenant) {}

    /**
     * @param  string  $permission  e.g. 'roster.publish'
     * @param  int|null  $accountId  the account being acted on
     * @param  int|null  $locationId  the location being acted on
     */
    public function allows(User $user, string $permission, ?int $accountId = null, ?int $locationId = null): bool
    {
        $accountId ??= $this->tenant->id();

        // An unknown permission, or one whose module has been switched off
        // product-wide, is denied outright -- including to a super admin.
        $moduleKey = $this->catalog()[$permission] ?? null;

        if ($moduleKey === null) {
            return false;
        }

        if ($accountId !== null && ! $this->moduleEnabled($moduleKey, $accountId)) {
            return false;
        }

        if ($user->is_admin) {
            return true;
        }

        // Everything below this line is account-scoped. No account, no grant.
        if ($accountId === null) {
            return false;
        }

        return $this->withTeam($accountId, fn () => $user->scopedRoles($locationId)
            ->contains(fn (Role $role) => $role->hasPermissionTo($permission)));
    }

    /**
     * Spatie keeps the active team in static state on the registrar, so a check
     * against one account would otherwise leak into the next. Set it, run, and
     * put back whatever was there -- including null.
     */
    private function withTeam(int $accountId, Closure $callback): mixed
    {
        $registrar = app(PermissionRegistrar::class);
        $previous = getPermissionsTeamId();

        $registrar->setPermissionsTeamId($accountId);

        try {
            return $callback();
        } finally {
            $registrar->setPermissionsTeamId($previous);
        }
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

    /**
     * Kept because grant and revoke call it. There is nothing per-user left to
     * flush: scopedRoles() queries live on every check, precisely so a stale
     * cache can never hand someone access they no longer hold. Spatie's own
     * cache covers role -> permission and invalidates itself on change.
     */
    public function flush(int $userId): void
    {
        // Intentionally empty. See the docblock before adding a cache here.
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
