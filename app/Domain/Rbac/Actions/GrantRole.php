<?php

namespace App\Domain\Rbac\Actions;

use App\Domain\Identity\Models\Location;
use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Data\GrantRoleData;
use App\Domain\Rbac\Models\Role;
use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Domain\Rbac\Support\RbacAudit;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * Grants a role to a user at a scope.
 *
 * The database enforces scope integrity and duplicate protection, but failing
 * at the constraint gives the user a 500. This validates first so the API can
 * answer properly, and lets the constraint remain the backstop.
 *
 * Takes one GrantRoleData rather than seven positional arguments: accountId
 * and locationId are both nullable ints, and transposing them used to be a
 * mistake nothing could catch.
 */
class GrantRole
{
    public function __invoke(GrantRoleData $data): UserRoleAssignment
    {
        $role = $data->role;
        $user = $data->user;
        $accountId = $data->accountId;
        $locationId = $data->locationId;

        $this->assertScopeMatches($role, $accountId, $locationId);
        $this->assertRoleAvailable($role, $accountId);
        $this->assertLocationInAccount($locationId, $accountId);
        $this->assertNotDuplicate($user, $role, $accountId, $locationId);

        $assignment = DB::transaction(fn () => UserRoleAssignment::create([
            'model_id' => $user->id,
            'model_type' => $user::class,
            'role_id' => $role->id,
            'scope_level' => $role->scope_level,
            'account_id' => $accountId,
            'location_id' => $locationId,
            'granted_by' => $data->grantedBy?->id,
            'grant_reason' => $data->reason,
            'valid_from' => now(),
            'valid_until' => $data->validUntil,
        ]));

        RbacAudit::record('role.granted', $assignment, [
            'user' => $user->name,
            'role' => $role->name,
            'scope_level' => $role->scope_level,
            'account_id' => $accountId,
            'location_id' => $locationId,
            'valid_until' => $data->validUntil,
            'reason' => $data->reason,
        ]);

        return $assignment;
    }

    private function assertScopeMatches(Role $role, ?int $accountId, ?int $locationId): void
    {
        $ok = match ($role->scope_level) {
            Role::SCOPE_ACCOUNT => $accountId !== null && $locationId === null,
            Role::SCOPE_LOCATION => $accountId !== null && $locationId !== null,
            default => false,
        };

        if (! $ok) {
            throw ValidationException::withMessages([
                'scope' => "A {$role->scope_level}-scoped role must be granted with ".match ($role->scope_level) {
                    Role::SCOPE_ACCOUNT => 'an account and no location.',
                    Role::SCOPE_LOCATION => 'both an account and a location.',
                    default => 'a valid scope.',
                },
            ]);
        }
    }

    /**
     * A role owned by another account would be written, audited as granted, and
     * then never match: Spatie's roles() only returns system roles and the active
     * team's own. Refuse it rather than record access that does not exist.
     */
    private function assertRoleAvailable(Role $role, int $accountId): void
    {
        if ($role->account_id !== null && $role->account_id !== $accountId) {
            throw ValidationException::withMessages([
                'role_id' => "{$role->name} belongs to another account and cannot be granted here.",
            ]);
        }
    }

    /**
     * Nothing downstream re-checks that a location sits inside the grant's
     * account, so a foreign location here would grant real access to another
     * tenant's site. acrossTenants() so the check does not depend on whichever
     * tenant the request happens to have resolved.
     */
    private function assertLocationInAccount(?int $locationId, int $accountId): void
    {
        if ($locationId === null) {
            return;
        }

        $inAccount = Location::acrossTenants()
            ->whereKey($locationId)
            ->where('account_id', $accountId)
            ->exists();

        if (! $inAccount) {
            throw ValidationException::withMessages([
                'location_id' => 'That location does not belong to the selected account.',
            ]);
        }
    }

    private function assertNotDuplicate(User $user, Role $role, ?int $accountId, ?int $locationId): void
    {
        $exists = UserRoleAssignment::query()
            ->where('model_id', $user->id)
            ->where('model_type', $user::class)
            ->where('role_id', $role->id)
            ->whereNull('revoked_at')
            ->where('account_id', $accountId)
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
