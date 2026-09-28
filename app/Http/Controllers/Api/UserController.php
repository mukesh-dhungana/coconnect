<?php

namespace App\Http\Controllers\Api;

use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Contracts\UserDirectory;
use App\Domain\Rbac\Data\NewUserData;
use App\Domain\Rbac\Models\Permission;
use App\Domain\Rbac\Services\PermissionCatalog;
use App\Domain\Rbac\Support\RbacAudit;
use App\Http\Controllers\Controller;
use App\Http\Requests\StoreUserRequest;
use App\Http\Requests\UpdateUserRequest;
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

    /**
     * Directory with the roles each person holds — the admin list view.
     *
     * A super administrator sees everyone. Anyone else sees only the people in
     * the account the request acts in, with only that account's roles: an
     * account administrator does not learn who else exists, or what a shared
     * person holds in another client's account.
     */
    public function index(Request $request): JsonResponse
    {
        $admin = $request->user()->is_admin;
        $accountId = $admin ? ($request->integer('account_id') ?: null) : $this->tenant->id();

        $people = $admin ? $this->users->all() : $this->users->inAccount($accountId);

        return $this->ok($people->map(fn (User $u) => [
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
            'permission_count' => count($this->catalog->permissionNames($u, $admin ? null : $accountId)),
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

    /**
     * Edit a person's profile.
     *
     * An account administrator may edit only people in their own account --
     * anyone else is a 404, as if they did not exist. Two more limits, because
     * a login is shared across accounts and email is how it is recovered:
     * they may not edit a super administrator, nor someone who also belongs
     * to another account. Changing either's email would hand over access the
     * editor does not administer. Those go to a super administrator.
     */
    public function update(UpdateUserRequest $request, User $user): JsonResponse
    {
        $actor = $request->user();
        $accountId = $this->tenant->id();

        abort_unless($this->users->visibleTo($actor, $user, $accountId), 404);

        if (! $actor->is_admin && ($user->is_admin || $user->belongsBeyond($accountId))) {
            return $this->failed('Only a super administrator can edit this person.', 403);
        }

        $changes = $this->users->update($user, $request->validated());

        RbacAudit::record('user.updated', $user, [
            'user'       => $user->name,
            'email'      => $user->email,
            'account_id' => $accountId,
            'changed'    => $changes,
        ]);

        return $this->ok([
            'id' => $user->id, 'name' => $user->name, 'email' => $user->email, 'mobile' => $user->mobile,
        ]);
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
