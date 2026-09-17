<?php

namespace App\Domain\Rbac\Actions;

use App\Domain\Rbac\Models\Role;
use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Domain\Rbac\Services\PermissionResolver;
use App\Domain\Rbac\Support\RbacAudit;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * Grants a role to a user at a scope.
 *
 * The database enforces scope integrity and duplicate protection, but failing
 * at the constraint gives the user a 500. This validates first so the API can
 * answer properly, and lets the constraint remain the backstop.
 */
class GrantRole
{
    public function __construct(private PermissionResolver $resolver) {}

    public function __invoke(
        User $user,
        Role $role,
        ?int $accountId = null,
        ?int $locationId = null,
        ?User $grantedBy = null,
        ?string $reason = null,
        ?string $validUntil = null,
    ): UserRoleAssignment {
        $this->assertScopeMatches($role, $accountId, $locationId);
        $this->assertNotDuplicate($user, $role, $accountId, $locationId);

        $assignment = DB::transaction(fn () => UserRoleAssignment::create([
            'user_id'      => $user->id,
            'role_id'      => $role->id,
            'scope_level'  => $role->scope_level,
            'account_id'   => $accountId,
            'location_id'  => $locationId,
            'granted_by'   => $grantedBy?->id,
            'grant_reason' => $reason,
            'valid_from'   => now(),
            'valid_until'  => $validUntil,
        ]));

        RbacAudit::record('role.granted', $assignment, [
            'user'        => $user->name,
            'role'        => $role->name,
            'scope_level' => $role->scope_level,
            'account_id'  => $accountId,
            'location_id' => $locationId,
            'valid_until' => $validUntil,
            'reason'      => $reason,
        ]);

        $this->resolver->flush($user->id);

        return $assignment;
    }

    private function assertScopeMatches(Role $role, ?int $accountId, ?int $locationId): void
    {
        $ok = match ($role->scope_level) {
            Role::SCOPE_GLOBAL   => $accountId === null && $locationId === null,
            Role::SCOPE_ACCOUNT  => $accountId !== null && $locationId === null,
            Role::SCOPE_LOCATION => $accountId !== null && $locationId !== null,
            default              => false,
        };

        if (! $ok) {
            throw ValidationException::withMessages([
                'scope' => "A {$role->scope_level}-scoped role must be granted with ".match ($role->scope_level) {
                    Role::SCOPE_GLOBAL   => 'no account and no location.',
                    Role::SCOPE_ACCOUNT  => 'an account and no location.',
                    Role::SCOPE_LOCATION => 'both an account and a location.',
                    default              => 'a valid scope.',
                },
            ]);
        }
    }

    private function assertNotDuplicate(User $user, Role $role, ?int $accountId, ?int $locationId): void
    {
        $exists = UserRoleAssignment::query()
            ->where('user_id', $user->id)
            ->where('role_id', $role->id)
            ->whereNull('revoked_at')
            ->when($accountId === null, fn ($q) => $q->whereNull('account_id'),
                                        fn ($q) => $q->where('account_id', $accountId))
            ->when($locationId === null, fn ($q) => $q->whereNull('location_id'),
                                         fn ($q) => $q->where('location_id', $locationId))
            ->exists();

        if ($exists) {
            throw ValidationException::withMessages([
                'role' => "{$user->name} already holds {$role->name} at this scope.",
            ]);
        }
    }
}
