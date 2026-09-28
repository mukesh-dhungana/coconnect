<?php

namespace App\Domain\Rbac\Contracts;

use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Data\NewUserData;
use Illuminate\Support\Collection;

interface UserDirectory
{
    /** Everyone, with the roles they hold eager-loaded. */
    public function all(): Collection;

    /**
     * The people in one account, with only that account's roles loaded -- an
     * account-level administrator must not learn what someone holds elsewhere.
     */
    public function inAccount(int $accountId): Collection;

    /**
     * May this viewer see or manage this person, acting inside this account?
     * A super administrator always may; anyone else only for a person in the
     * account the request acts in.
     */
    public function visibleTo(User $viewer, User $person, ?int $accountId): bool;

    public function create(NewUserData $data): User;

    /** Change profile fields; returns what changed, for the audit entry. */
    public function update(User $user, array $attributes): array;
}
