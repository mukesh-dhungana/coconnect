<?php

namespace App\Http\Controllers\Api;

use App\Domain\Identity\Models\Account;
use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Contracts\UserDirectory;
use App\Domain\Rbac\Data\NewUserData;
use App\Domain\Rbac\Models\Permission;
use App\Domain\Rbac\Services\PermissionCatalog;
use App\Domain\Rbac\Support\RbacAudit;
use App\Http\Controllers\Controller;
use App\Http\Requests\StoreUserRequest;
use App\Support\Concerns\RespondsWithJson;
use App\Support\Tenancy\TenantContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class UserController extends Controller
{
    use RespondsWithJson;

    public function __construct(
        private PermissionCatalog $catalog,
        private UserDirectory $users,
        private TenantContext $tenant,
    ) {}

    /** Directory with the roles each person holds — the admin list view. */
    public function index(Request $request): JsonResponse
    {
        $accountId = $request->integer('account_id') ?: null;

        return $this->ok($this->users->all()->map(fn (User $u) => [
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
            'permission_count' => count($this->catalog->permissionNames($u)),
            'modules' => $accountId ? $this->catalog->visibleModules($u, $accountId) : [],
        ]));
    }

    /**
     * Create a person.
     *
     * A user is created with no roles at all — deliberately. Access is granted
     * afterwards, as an explicit, audited act, so nobody acquires permissions
     * merely by existing.
     *
     * The person joins the account the request acts inside. `tenant` resolves
     * that from account_id (or the caller's only account) and refuses one the
     * caller holds no grant in, and `permission:` has already been answered
     * for it -- so an account-level grant can only ever add people to its own
     * account. Only a super administrator, acting with no account, creates
     * someone who belongs to none.
     */
    public function store(StoreUserRequest $request): JsonResponse
    {
        $data = NewUserData::fromArray([
            ...$request->validated(),
            'account_id' => $this->tenant->id(),
        ]);
        $user = $this->users->create($data);

        RbacAudit::record('user.created', $user, [
            'user'       => $user->name,
            'email'      => $user->email,
            'account_id' => $data->accountId,
        ]);

        return $this->created([
            'id' => $user->id, 'name' => $user->name, 'email' => $user->email,
        ]);
    }

    /** Accounts and their locations — drives the scope pickers. */
    public function accounts(): JsonResponse
    {
        return $this->ok(
            Account::with('locations:id,account_id,name')->orderBy('name')->get()
                ->map(fn ($a) => [
                    'id'        => $a->id,
                    'name'      => $a->name,
                    'locations' => $a->locations->map(fn ($l) => ['id' => $l->id, 'name' => $l->name])->values(),
                ])
        );
    }

    /** Every permission, grouped by module — drives the role editor. */
    public function permissions(): JsonResponse
    {
        return $this->ok(
            Permission::with('module:id,key,name')->orderBy('name')->get()
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
