<?php

namespace App\Domain\Rbac\Actions;

use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Domain\Rbac\Support\RbacAudit;

/**
 * Revokes rather than deletes. The row stays, so "who had access in March?"
 * remains answerable, and the generated active_guard column drops it out of
 * the unique index so the same role can be granted again later.
 */
class RevokeRole
{
    public function __invoke(UserRoleAssignment $assignment, ?User $revokedBy = null): UserRoleAssignment
    {
        $assignment->update([
            'revoked_at' => now(),
            'revoked_by' => $revokedBy?->id,
        ]);

        RbacAudit::record('role.revoked', $assignment, [
            'user' => $assignment->user?->name,
            'role' => $assignment->role?->name,
            'scope_level' => $assignment->scope_level,
            'account_id' => $assignment->account_id,
            'location_id' => $assignment->location_id,
        ]);

        return $assignment->fresh();
    }
}
