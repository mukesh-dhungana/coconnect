<?php

namespace App\Http\Controllers\Api;

use App\Domain\Identity\Models\{Account, User};
use App\Domain\Rbac\Services\PermissionResolver;
use App\Http\Controllers\Controller;
use App\Domain\Rbac\Support\RbacAudit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

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

    /**
     * Create a person.
     *
     * A user is created with no roles at all — deliberately. Access is granted
     * afterwards, as an explicit, audited act, so nobody acquires permissions
     * merely by existing.
     */
    public function store(Request $request)
    {
        $data = $request->validate([
            'first_name' => ['required', 'string', 'max:100'],
            'last_name'  => ['required', 'string', 'max:100'],
            'email'      => ['required', 'email', 'max:190', 'unique:users,email'],
            'mobile'     => ['nullable', 'string', 'max:20', 'unique:users,mobile'],
            'account_id' => ['nullable', 'exists:accounts,id'],
        ]);

        $user = User::create([
            'first_name' => $data['first_name'],
            'last_name'  => $data['last_name'],
            'uuid'       => (string) Str::uuid(),
            'email'      => $data['email'],
            'mobile'     => $data['mobile'] ?? null,
            // A random secret: the account is unusable until the person sets
            // their own password through the invite flow.
            'password'   => Hash::make(Str::random(32)),
        ]);

        // Membership is not permission — it only places them in the account.
        if (! empty($data['account_id'])) {
            $user->accounts()->attach($data['account_id'], [
                'type' => 'employee', 'source' => 'admin', 'invited_at' => now(),
            ]);
        }

        RbacAudit::record('user.created', $user, [
            'user'       => $user->name,
            'email'      => $user->email,
            'account_id' => $data['account_id'] ?? null,
        ]);

        return response()->json([
            'id' => $user->id, 'name' => $user->name, 'email' => $user->email,
        ], 201);
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
