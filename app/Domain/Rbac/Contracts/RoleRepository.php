<?php

namespace App\Domain\Rbac\Contracts;

use App\Domain\Rbac\Models\Role;
use Illuminate\Support\Collection;

/**
 * Controllers depend on this, not on Eloquent.
 *
 * The point is not swapping MySQL for something else — it is that "which roles
 * can this account use" is one rule with one home. When it changes, it changes
 * once.
 */
interface RoleRepository
{
    /** System roles plus the account's own. */
    public function availableTo(?int $accountId): Collection;

    public function findOrFail(int $id): Role;

    public function create(array $attributes): Role;

    /** @return array{added: string[], removed: string[]} */
    public function syncPermissions(Role $role, array $permissionNames): array;

    /** Users holding this role, for cache invalidation. */
    public function holderIds(Role $role): array;
}
