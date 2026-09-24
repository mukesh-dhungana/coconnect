<?php

namespace App\Http\Controllers\Api;

use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Actions\GrantRole;
use App\Domain\Rbac\Actions\RevokeRole;
use App\Domain\Rbac\Contracts\RoleRepository;
use App\Domain\Rbac\Data\GrantRoleData;
use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Domain\Rbac\Services\PermissionCatalog;
use App\Http\Controllers\Controller;
use App\Http\Requests\CheckPermissionRequest;
use App\Http\Requests\GrantRoleRequest;
use App\Support\Concerns\RespondsWithJson;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AssignmentController extends Controller
{
    use RespondsWithJson;

    public function __construct(
        private GrantRole $grant,
        private RevokeRole $revoke,
        private PermissionCatalog $catalog,
        private RoleRepository $roles,
    ) {}

    /** Every role a user holds, active or not. */
    public function index(User $user): JsonResponse
    {
        $assignments = $user->roleAssignments()
            ->with(['role:id,name,scope_level', 'account:id,name', 'location:id,name', 'grantedBy:id,first_name,last_name'])
            ->orderByDesc('created_at')
            ->get()
            ->map(fn ($a) => [
                'id'          => $a->id,
                'role'        => $a->role->name,
                'scope_level' => $a->scope_level,
                'account'     => $a->account?->name,
                'location'    => $a->location?->name,
                'granted_by'  => $a->grantedBy?->name,
                'valid_until' => $a->valid_until?->toIso8601String(),
                'status'      => $a->status,
            ]);

        return $this->ok([
            'user'        => ['id' => $user->id, 'name' => $user->name, 'email' => $user->email],
            'assignments' => $assignments,
            'permissions' => $this->catalog->permissionNames($user),
        ]);
    }

    public function store(GrantRoleRequest $request, User $user): JsonResponse
    {
        $assignment = ($this->grant)(GrantRoleData::fromRequest(
            user: $user,
            role: $this->roles->findOrFail((int) $request->validated('role_id')),
            input: $request->validated(),
            actor: $request->user(),
        ));

        return $this->created($assignment);
    }

    /**
     * The route's permission check answers for the account the request
     * resolved, which a DELETE by id does not tie to the assignment. Ask again
     * for the assignment's own account, or an account-level grant could
     * revoke access in an account it does not cover.
     */
    public function destroy(Request $request, UserRoleAssignment $assignment): JsonResponse
    {
        abort_unless(
            $request->user()->hasPermission('system.user_manage', $assignment->account_id),
            403,
            'You cannot manage access in that account.',
        );

        return $this->ok(($this->revoke)($assignment, $request->user()));
    }

    /** The question the whole module exists to answer. */
    public function check(CheckPermissionRequest $request, User $user): JsonResponse
    {
        $data = $request->validated();

        return $this->ok([
            'user'        => $user->name,
            'permission'  => $data['permission'],
            'account_id'  => $data['account_id'] ?? null,
            'location_id' => $data['location_id'] ?? null,
            'allowed'     => $user->hasPermission(
                $data['permission'],
                $data['account_id'] ?? null,
                $data['location_id'] ?? null,
            ),
        ]);
    }
}
