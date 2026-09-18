<?php

namespace App\Domain\Rbac\Data;

use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Models\Role;

/**
 * What it takes to grant a role, as one immutable value.
 *
 * The action used to take seven positional arguments; a caller could transpose
 * accountId and locationId without the type system noticing. A readonly object
 * makes the call site say what it means and cannot be half-built.
 */
final readonly class GrantRoleData
{
    public function __construct(
        public User $user,
        public Role $role,
        public ?int $accountId = null,
        public ?int $locationId = null,
        public ?User $grantedBy = null,
        public ?string $reason = null,
        public ?string $validUntil = null,
    ) {}

    public static function fromRequest(User $user, Role $role, array $input, ?User $actor): self
    {
        return new self(
            user: $user,
            role: $role,
            accountId: $input['account_id'] ?? null,
            locationId: $input['location_id'] ?? null,
            grantedBy: $actor,
            reason: $input['reason'] ?? null,
            validUntil: $input['valid_until'] ?? null,
        );
    }

    /** The scope this grant claims, for validation and for the audit entry. */
    public function scope(): array
    {
        return ['account_id' => $this->accountId, 'location_id' => $this->locationId];
    }
}
