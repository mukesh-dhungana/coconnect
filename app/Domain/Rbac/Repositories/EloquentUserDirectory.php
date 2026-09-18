<?php

namespace App\Domain\Rbac\Repositories;

use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Contracts\UserDirectory;
use App\Domain\Rbac\Data\NewUserData;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class EloquentUserDirectory implements UserDirectory
{
    public function all(): Collection
    {
        return User::with([
            'roleAssignments.role:id,name,scope_level',
            'roleAssignments.account:id,name',
            'roleAssignments.location:id,name',
        ])->orderBy('first_name')->get();
    }

    public function create(NewUserData $data): User
    {
        $user = User::create([
            'first_name' => $data->firstName,
            'last_name'  => $data->lastName,
            'uuid'       => (string) Str::uuid(),
            'email'      => $data->email,
            'mobile'     => $data->mobile,
            // Random secret: the account is unusable until the person sets
            // their own password through the invite flow.
            'password'   => Hash::make(Str::random(32)),
        ]);

        if ($data->accountId) {
            // Membership places them in the account; it grants nothing.
            $user->accounts()->attach($data->accountId, [
                'type' => 'employee', 'source' => 'admin', 'invited_at' => now(),
            ]);
        }

        return $user;
    }
}
