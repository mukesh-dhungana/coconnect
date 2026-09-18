<?php

namespace App\Domain\Rbac\Contracts;

use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Data\NewUserData;
use Illuminate\Support\Collection;

interface UserDirectory
{
    /** Everyone, with the roles they hold eager-loaded. */
    public function all(): Collection;

    public function create(NewUserData $data): User;
}
