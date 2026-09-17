<?php

use App\Domain\Rbac\Actions\GrantRole;
use App\Domain\Rbac\Actions\RevokeRole;
use App\Domain\Identity\Models\{Account, Location, User};
use App\Domain\Rbac\Models\{Module, Permission, Role, UserRoleAssignment};
use App\Domain\Rbac\Services\PermissionResolver;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

function makeUser(string $name = 'Test User'): User
{
    [$first, $last] = explode(' ', $name, 2);

    return User::create([
        'first_name' => $first, 'last_name' => $last,
        'uuid' => (string) Str::uuid(),
        'email' => Str::slug($name).'@example.com',
        'mobile' => '+614'.random_int(10000000, 99999999),
    ]);
}

function scenario(): array
{
    $module = Module::create(['key' => 'roster', 'name' => 'Roster']);
    $perm   = Permission::create(['name' => 'roster.publish', 'module_id' => $module->id]);

    $account  = Account::create(['name' => 'Acme', 'slug' => 'acme']);
    $other    = Account::create(['name' => 'Other', 'slug' => 'other']);
    $location = Location::create(['account_id' => $account->id, 'name' => 'Village', 'slug' => 'village']);
    $location2= Location::create(['account_id' => $account->id, 'name' => 'Site', 'slug' => 'site']);

    $account->modules()->attach($module->id, ['is_enabled' => true]);
    $other->modules()->attach($module->id, ['is_enabled' => true]);

    return compact('module', 'perm', 'account', 'other', 'location', 'location2');
}

function roleWith(string $scope, Permission $perm, ?string $key = null): Role
{
    $role = Role::create([
        'key' => $key ?? $scope.'_role', 'name' => ucfirst($scope).' Role',
        'scope_level' => $scope, 'is_system' => true,
    ]);
    $role->permissions()->attach($perm->id);

    return $role;
}

it('grants a global role across every account', function () {
    ['perm' => $perm, 'account' => $account, 'other' => $other] = scenario();
    $user = makeUser('Glenda Global');

    app(GrantRole::class)($user, roleWith('global', $perm));

    expect($user->hasPermission('roster.publish', $account->id))->toBeTrue()
        ->and($user->hasPermission('roster.publish', $other->id))->toBeTrue();
});

it('confines an account role to its own account', function () {
    ['perm' => $perm, 'account' => $account, 'other' => $other] = scenario();
    $user = makeUser('Alan Account');

    app(GrantRole::class)($user, roleWith('account', $perm), $account->id);

    expect($user->hasPermission('roster.publish', $account->id))->toBeTrue()
        ->and($user->hasPermission('roster.publish', $other->id))->toBeFalse();
});

it('confines a location role to its own location', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc, 'location2' => $loc2] = scenario();
    $user = makeUser('Lara Location');

    app(GrantRole::class)($user, roleWith('location', $perm), $account->id, $loc->id);

    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue()
        ->and($user->hasPermission('roster.publish', $account->id, $loc2->id))->toBeFalse();
});

it('denies everything when the module is disabled for that account', function () {
    ['module' => $module, 'perm' => $perm, 'account' => $account] = scenario();
    $user = makeUser('Glenda Global');

    app(GrantRole::class)($user, roleWith('global', $perm));
    expect($user->hasPermission('roster.publish', $account->id))->toBeTrue();

    // Commercial boundary: the client has not bought this module.
    $account->modules()->updateExistingPivot($module->id, ['is_enabled' => false]);
    app(PermissionResolver::class)->flush($user->id);
    cache()->forget("rbac:module:{$account->id}:roster");

    expect($user->hasPermission('roster.publish', $account->id))->toBeFalse();
});

it('unions permissions across several roles held at once', function () {
    ['module' => $module, 'perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $second = Permission::create(['name' => 'roster.edit', 'module_id' => $module->id]);

    $roleA = roleWith('location', $perm, 'role_a');
    $roleB = Role::create(['key' => 'role_b', 'name' => 'Role B', 'scope_level' => 'location', 'is_system' => true]);
    $roleB->permissions()->attach($second->id);

    $user = makeUser('Multi Role');
    app(GrantRole::class)($user, $roleA, $account->id, $loc->id);
    app(GrantRole::class)($user, $roleB, $account->id, $loc->id);

    expect($user->roleAssignments()->active()->count())->toBe(2)
        ->and($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue()
        ->and($user->hasPermission('roster.edit', $account->id, $loc->id))->toBeTrue();
});

it('drops a temporary grant once it expires', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $user = makeUser('Temp Elevated');

    app(GrantRole::class)(
        user: $user, role: roleWith('location', $perm),
        accountId: $account->id, locationId: $loc->id,
        validUntil: now()->addHour()->toDateTimeString(),
    );
    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue();

    $this->travel(2)->hours();
    app(PermissionResolver::class)->flush($user->id);

    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeFalse();
});

it('rejects a duplicate grant at the same scope', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $user = makeUser('Dupe Test');
    $role = roleWith('location', $perm);

    app(GrantRole::class)($user, $role, $account->id, $loc->id);
    app(GrantRole::class)($user, $role, $account->id, $loc->id);
})->throws(ValidationException::class);

it('rejects a location role granted without a location', function () {
    ['perm' => $perm, 'account' => $account] = scenario();

    app(GrantRole::class)(makeUser('Bad Scope'), roleWith('location', $perm), $account->id);
})->throws(ValidationException::class);

it('rejects a global role granted with a scope', function () {
    ['perm' => $perm, 'account' => $account] = scenario();

    app(GrantRole::class)(makeUser('Bad Global'), roleWith('global', $perm), $account->id);
})->throws(ValidationException::class);

it('revokes without deleting, and allows a later re-grant', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $user = makeUser('Revoke Test');
    $role = roleWith('location', $perm);

    $assignment = app(GrantRole::class)($user, $role, $account->id, $loc->id);
    app(RevokeRole::class)($assignment);

    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeFalse()
        ->and(UserRoleAssignment::count())->toBe(1);          // history kept

    app(GrantRole::class)($user, $role, $account->id, $loc->id);

    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue()
        ->and(UserRoleAssignment::count())->toBe(2);          // both rows retained
});

it('denies a permission nobody granted', function () {
    ['account' => $account] = scenario();

    expect(makeUser('Nobody Special')->hasPermission('roster.publish', $account->id))->toBeFalse();
});
