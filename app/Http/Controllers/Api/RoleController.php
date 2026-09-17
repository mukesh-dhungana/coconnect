<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Domain\Rbac\Models\Permission;
use App\Domain\Rbac\Models\Role;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;

class RoleController extends Controller
{
    /** System roles plus, optionally, one account's own roles. */
    public function index(Request $request)
    {
        $accountId = $request->integer('account_id') ?: null;

        return response()->json(
            Role::availableTo($accountId)
                ->with('permissions:id,name,module_id')
                ->withCount('assignments')
                ->orderBy('scope_level')->orderBy('name')
                ->get()
        );
    }

    public function store(Request $request)
    {
        $data = $request->validate([
            'account_id'  => ['nullable', 'exists:accounts,id'],
            'key'         => ['required', 'string', 'max:100', 'regex:/^[a-z][a-z0-9_]*$/'],
            'name'        => ['required', 'string', 'max:255'],
            'description' => ['nullable', 'string', 'max:255'],
            'scope_level' => ['required', Rule::in(['global', 'account', 'location'])],
        ]);

        $exists = Role::where('account_id', $data['account_id'] ?? null)
            ->where('key', $data['key'])->exists();

        if ($exists) {
            return response()->json(['message' => 'A role with that key already exists in this scope.'], 422);
        }

        return response()->json(Role::create($data + ['is_system' => false]), 201);
    }

    /** Replace a role's permission set. */
    public function syncPermissions(Request $request, Role $role)
    {
        $data = $request->validate([
            'permissions'   => ['present', 'array'],
            'permissions.*' => ['string', 'exists:permissions,name'],
        ]);

        $ids = Permission::whereIn('name', $data['permissions'])->pluck('id')->all();
        $role->permissions()->sync($ids);

        // Anyone holding this role has a stale cached grant set.
        $role->assignments()->distinct()->pluck('user_id')
            ->each(fn ($id) => cache()->forget("rbac:grants:{$id}"));

        return response()->json([
            'role'        => $role->name,
            'permissions' => $role->permissions()->pluck('name'),
        ]);
    }
}
