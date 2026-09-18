<?php

namespace App\Http\Controllers\Api;

use App\Domain\Rbac\Contracts\RoleRepository;
use App\Domain\Rbac\Models\Role;
use App\Domain\Rbac\Support\RbacAudit;
use App\Http\Controllers\Controller;
use App\Http\Requests\StoreRoleRequest;
use App\Http\Requests\SyncRolePermissionsRequest;
use App\Support\Concerns\RespondsWithJson;
use App\Support\Tenancy\TenantContext;
use Illuminate\Http\JsonResponse;

class RoleController extends Controller
{
    use RespondsWithJson;

    public function __construct(
        private RoleRepository $roles,
        private TenantContext $tenant,
    ) {}

    public function index(): JsonResponse
    {
        return $this->ok($this->roles->availableTo($this->tenant->id()));
    }

    public function store(StoreRoleRequest $request): JsonResponse
    {
        $role = $this->roles->create($request->validated());

        RbacAudit::record('role.created', $role, [
            'role'        => $role->name,
            'scope_level' => $role->scope_level,
            'account_id'  => $role->account_id,
        ]);

        return $this->created($role);
    }

    public function syncPermissions(SyncRolePermissionsRequest $request, Role $role): JsonResponse
    {
        $changes = $this->roles->syncPermissions($role, $request->validated('permissions'));

        RbacAudit::record('role.permissions_changed', $role, [
            'role' => $role->name,
        ] + $changes);

        // Anyone holding this role has a stale cached grant set.
        foreach ($this->roles->holderIds($role) as $userId) {
            cache()->forget("rbac:grants:{$userId}");
        }

        return $this->ok([
            'role'        => $role->name,
            'permissions' => $role->permissions()->pluck('name'),
            'changes'     => $changes,
        ]);
    }
}
