<?php

namespace App\Http\Controllers\Api;

use App\Domain\Rbac\Actions\GrantRole;
use App\Domain\Rbac\Actions\RevokeRole;
use App\Http\Controllers\Controller;
use App\Domain\Rbac\Models\Role;
use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Domain\Rbac\Services\PermissionResolver;
use Illuminate\Http\Request;

class AssignmentController extends Controller
{
    public function __construct(
        private GrantRole $grant,
        private RevokeRole $revoke,
        private PermissionResolver $resolver,
    ) {}

    /** Every role a user holds, active or not. */
    public function index(User $user)
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

        return response()->json([
            'user'        => ['id' => $user->id, 'name' => $user->name, 'email' => $user->email],
            'assignments' => $assignments,
            'permissions' => $this->resolver->permissionNames($user),
        ]);
    }

    public function store(Request $request, User $user)
    {
        $data = $request->validate([
            'role_id'     => ['required', 'exists:roles,id'],
            'account_id'  => ['nullable', 'exists:accounts,id'],
            'location_id' => ['nullable', 'exists:locations,id'],
            'valid_until' => ['nullable', 'date', 'after:now'],
            'reason'      => ['nullable', 'string', 'max:255'],
        ]);

        $assignment = ($this->grant)(
            user: $user,
            role: Role::findOrFail($data['role_id']),
            accountId: $data['account_id'] ?? null,
            locationId: $data['location_id'] ?? null,
            grantedBy: $request->user(),
            reason: $data['reason'] ?? null,
            validUntil: $data['valid_until'] ?? null,
        );

        return response()->json($assignment, 201);
    }

    public function destroy(Request $request, UserRoleAssignment $assignment)
    {
        return response()->json(($this->revoke)($assignment, $request->user()));
    }

    /** The question the whole module exists to answer. */
    public function check(Request $request, User $user)
    {
        $data = $request->validate([
            'permission'  => ['required', 'string'],
            'account_id'  => ['nullable', 'integer'],
            'location_id' => ['nullable', 'integer'],
        ]);

        $allowed = $this->resolver->allows(
            $user,
            $data['permission'],
            $data['account_id'] ?? null,
            $data['location_id'] ?? null,
        );

        return response()->json([
            'user'        => $user->name,
            'permission'  => $data['permission'],
            'account_id'  => $data['account_id'] ?? null,
            'location_id' => $data['location_id'] ?? null,
            'allowed'     => $allowed,
        ]);
    }
}
