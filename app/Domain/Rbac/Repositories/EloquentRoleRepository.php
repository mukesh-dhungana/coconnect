<?php

namespace App\Domain\Rbac\Repositories;

use App\Domain\Rbac\Contracts\RoleRepository;
use App\Domain\Rbac\Models\Permission;
use App\Domain\Rbac\Models\Role;
use Illuminate\Support\Collection;

class EloquentRoleRepository implements RoleRepository
{
    public function availableTo(?int $accountId): Collection
    {
        return Role::query()
            ->availableTo($accountId)
            ->with('permissions:id,name,module_id')
            ->withCount('assignments')
            ->orderBy('scope_level')
            ->orderBy('name')
            ->get();
    }

    public function findOrFail(int $id): Role
    {
        return Role::findOrFail($id);
    }

    public function create(array $attributes): Role
    {
        return Role::create($attributes + ['is_system' => false]);
    }

    public function syncPermissions(Role $role, array $permissionNames): array
    {
        $before = $role->permissions()->pluck('name')->sort()->values()->all();

        $role->permissions()->sync(
            Permission::whereIn('name', $permissionNames)->pluck('id')->all()
        );

        $after = $role->permissions()->pluck('name')->sort()->values()->all();

        return [
            'added'   => array_values(array_diff($after, $before)),
            'removed' => array_values(array_diff($before, $after)),
        ];
    }

    public function holderIds(Role $role): array
    {
        return $role->assignments()->distinct()->pluck('user_id')
            ->map(fn ($id) => (int) $id)->all();
    }
}
