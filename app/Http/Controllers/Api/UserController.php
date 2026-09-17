<?php

namespace App\Http\Controllers\Api;

use App\Domain\Identity\Models\{Account, User};
use App\Domain\Rbac\Services\PermissionResolver;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function __construct(private PermissionResolver $resolver) {}

    /** Directory with the roles each person holds — the admin list view. */
    public function index(Request $request)
    {
        $accountId = $request->integer('account_id') ?: null;

        $users = User::with([
            'roleAssignments.role:id,name,scope_level',
            'roleAssignments.account:id,name',
            'roleAssignments.location:id,name',
        ])->orderBy('first_name')->get();

        return response()->json($users->map(fn (User $u) => [
            'id'    => $u->id,
            'name'  => $u->name,
            'email' => $u->email,
            'assignments' => $u->roleAssignments->sortByDesc('created_at')->map(fn ($a) => [
                'id'          => $a->id,
                'role'        => $a->role->name,
                'role_id'     => $a->role_id,
                'scope_level' => $a->scope_level,
                'account'     => $a->account?->name,
                'location'    => $a->location?->name,
                'valid_until' => $a->valid_until?->toIso8601String(),
                'status'      => $a->status,
            ])->values(),
            'permission_count' => count($this->resolver->permissionNames($u)),
            'modules' => $accountId ? $this->resolver->visibleModules($u, $accountId) : [],
        ]));
    }

    /** Accounts and their locations — drives the scope pickers. */
    public function accounts()
    {
        return response()->json(
            Account::with('locations:id,account_id,name')->orderBy('name')->get()
                ->map(fn ($a) => [
                    'id'        => $a->id,
                    'name'      => $a->name,
                    'locations' => $a->locations->map(fn ($l) => ['id' => $l->id, 'name' => $l->name])->values(),
                ])
        );
    }

    /** Every permission, grouped by module — drives the role editor. */
    public function permissions()
    {
        return response()->json(
            \App\Domain\Rbac\Models\Permission::with('module:id,key,name')
                ->orderBy('name')->get()
                ->map(fn ($p) => [
                    'name'         => $p->name,
                    'module'       => $p->module->key,
                    'module_name'  => $p->module->name,
                    'description'  => $p->description,
                    'is_high_risk' => $p->is_high_risk,
                ])
        );
    }
}
