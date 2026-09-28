<?php

namespace App\Domain\Rbac\Console;

use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Domain\Rbac\Support\RbacAudit;
use Illuminate\Console\Command;

/**
 * Writes a role.expired audit entry for every temporary grant that has run out.
 *
 * Access is NOT cut off here: every permission check already ignores a grant
 * past its valid_until, to the second. This only makes the expiry visible in
 * the audit log, dated at valid_until rather than at whenever the job ran, so
 * the log never suggests access lasted longer than it did.
 *
 * Scheduled in routes/console.php. Safe to run twice or on two servers at once:
 * each grant is claimed with a conditional update before it is logged.
 */
class RecordExpiredGrants extends Command
{
    protected $signature = 'rbac:record-expiries';

    protected $description = 'Record a role.expired audit entry for each temporary grant that has expired';

    public function handle(): int
    {
        $recorded = 0;

        UserRoleAssignment::query()
            ->with(['user', 'role'])
            ->whereNotNull('valid_until')
            ->where('valid_until', '<=', now())
            ->whereNull('expiry_recorded_at')
            // Revoked before it ran out: role.revoked already ended it.
            ->where(fn ($q) => $q->whereNull('revoked_at')->orWhereColumn('revoked_at', '>', 'valid_until'))
            ->chunkById(200, function ($assignments) use (&$recorded) {
                foreach ($assignments as $assignment) {
                    $claimed = UserRoleAssignment::whereKey($assignment->id)
                        ->whereNull('expiry_recorded_at')
                        ->update(['expiry_recorded_at' => now()]);

                    if ($claimed === 0) {
                        continue;   // another run got there first
                    }

                    RbacAudit::record('role.expired', $assignment, [
                        'user' => $assignment->user?->name,
                        'role' => $assignment->role?->name,
                        'scope_level' => $assignment->scope_level,
                        'account_id' => $assignment->account_id,
                        'location_id' => $assignment->location_id,
                        'valid_until' => $assignment->valid_until->toIso8601String(),
                        'reason' => $assignment->grant_reason,
                    ], at: $assignment->valid_until);

                    $recorded++;
                }
            });

        $this->components->info("Recorded {$recorded} expired grant(s).");

        return self::SUCCESS;
    }
}
