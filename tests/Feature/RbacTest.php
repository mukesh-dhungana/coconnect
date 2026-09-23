<?php

use App\Domain\Identity\Models\Account;
use App\Domain\Identity\Models\Location;
use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Actions\GrantRole;
use App\Domain\Rbac\Actions\RevokeRole;
use App\Domain\Rbac\Data\GrantRoleData;
use App\Domain\Rbac\Models\Module;
use App\Domain\Rbac\Models\Permission;
use App\Domain\Rbac\Models\Role;
use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Domain\Rbac\Services\PermissionResolver;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

function makeUser(string $name = 'Test User', bool $superAdmin = false): User
{
    [$first, $last] = explode(' ', $name, 2);

    return User::create([
        'first_name' => $first, 'last_name' => $last,
        'uuid' => (string) Str::uuid(),
        'email' => Str::slug($name).'@example.com',
        'mobile' => '+614'.random_int(10000000, 99999999),
        'is_admin' => $superAdmin,
    ]);
}

function scenario(): array
{
    $module = Module::create(['key' => 'roster', 'name' => 'Roster']);
    $perm = Permission::create(['name' => 'roster.publish', 'module_id' => $module->id]);

    $account = Account::create(['name' => 'Acme', 'slug' => 'acme']);
    $other = Account::create(['name' => 'Other', 'slug' => 'other']);
    $location = Location::create(['account_id' => $account->id, 'name' => 'Village', 'slug' => 'village']);
    $location2 = Location::create(['account_id' => $account->id, 'name' => 'Site', 'slug' => 'site']);

    $account->modules()->attach($module->id, ['is_enabled' => true]);
    $other->modules()->attach($module->id, ['is_enabled' => true]);

    return compact('module', 'perm', 'account', 'other', 'location', 'location2');
}

function roleWith(string $scope, Permission $perm, ?string $key = null): Role
{
    $role = Role::create([
        'account_id' => null,           // system role, usable by every account
        'key' => $key ?? $scope.'_role', 'name' => ucfirst($scope).' Role',
        'scope_level' => $scope, 'is_system' => true,
    ]);
    $role->permissions()->attach($perm->id);

    return $role;
}

/** Builds the DTO so the call sites stay short. */
function grant(User $user, Role $role, ?int $accountId = null, ?int $locationId = null,
    ?string $validUntil = null): UserRoleAssignment
{
    return app(GrantRole::class)(new GrantRoleData(
        user: $user, role: $role, accountId: $accountId,
        locationId: $locationId, validUntil: $validUntil,
    ));
}

// ---------------------------------------------------------------------------
// Global scope: the super administrator flag
// ---------------------------------------------------------------------------

it('gives a super admin every permission in every account, with no grants at all', function () {
    ['account' => $account, 'other' => $other] = scenario();
    $user = makeUser('Glenda Global', superAdmin: true);

    expect($user->roleAssignments()->count())->toBe(0)
        ->and($user->hasPermission('roster.publish', $account->id))->toBeTrue()
        ->and($user->hasPermission('roster.publish', $other->id))->toBeTrue()
        ->and($user->hasPermission('roster.publish', $account->id, null))->toBeTrue();
});

it('still denies a super admin a permission that does not exist', function () {
    ['account' => $account] = scenario();

    expect(makeUser('Glenda Global', superAdmin: true)
        ->hasPermission('roster.invented', $account->id))->toBeFalse();
});

// ---------------------------------------------------------------------------
// Account and location scope
// ---------------------------------------------------------------------------

it('confines an account role to its own account', function () {
    ['perm' => $perm, 'account' => $account, 'other' => $other] = scenario();
    $user = makeUser('Alan Account');

    grant($user, roleWith('account', $perm), $account->id);

    expect($user->hasPermission('roster.publish', $account->id))->toBeTrue()
        ->and($user->hasPermission('roster.publish', $other->id))->toBeFalse();
});

it('lets an account role reach every location inside that account', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc, 'location2' => $loc2] = scenario();
    $user = makeUser('Alan Account');

    grant($user, roleWith('account', $perm), $account->id);

    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue()
        ->and($user->hasPermission('roster.publish', $account->id, $loc2->id))->toBeTrue();
});

it('confines a location role to its own location', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc, 'location2' => $loc2] = scenario();
    $user = makeUser('Lara Location');

    grant($user, roleWith('location', $perm), $account->id, $loc->id);

    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue()
        ->and($user->hasPermission('roster.publish', $account->id, $loc2->id))->toBeFalse();
});

it('does not let a location role answer an account-wide question', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $user = makeUser('Lara Location');

    grant($user, roleWith('location', $perm), $account->id, $loc->id);

    // No location named means "anywhere in the account", which this grant is not.
    expect($user->hasPermission('roster.publish', $account->id))->toBeFalse();
});

it('holds the same role at two locations in one account', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc, 'location2' => $loc2] = scenario();
    $user = makeUser('Two Sites');
    $role = roleWith('location', $perm);

    // Spatie's own primary key on model_has_roles would forbid the second row.
    grant($user, $role, $account->id, $loc->id);
    grant($user, $role, $account->id, $loc2->id);

    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue()
        ->and($user->hasPermission('roster.publish', $account->id, $loc2->id))->toBeTrue();
});

// ---------------------------------------------------------------------------
// The commercial boundary
// ---------------------------------------------------------------------------

it('denies everything when the module is disabled for that account', function () {
    ['module' => $module, 'perm' => $perm, 'account' => $account] = scenario();
    $user = makeUser('Alan Account');

    grant($user, roleWith('account', $perm), $account->id);
    expect($user->hasPermission('roster.publish', $account->id))->toBeTrue();

    // Commercial boundary: the client has not bought this module.
    $account->modules()->updateExistingPivot($module->id, ['is_enabled' => false]);
    app(PermissionResolver::class)->flushModule('roster', $account->id);

    expect($user->hasPermission('roster.publish', $account->id))->toBeFalse();
});

it('denies a super admin a module the account has not bought', function () {
    ['module' => $module, 'account' => $account] = scenario();
    $user = makeUser('Glenda Global', superAdmin: true);

    $account->modules()->updateExistingPivot($module->id, ['is_enabled' => false]);
    app(PermissionResolver::class)->flushModule('roster', $account->id);

    // is_admin is checked AFTER module enablement, on purpose.
    expect($user->hasPermission('roster.publish', $account->id))->toBeFalse();
});

// ---------------------------------------------------------------------------
// Multiple roles, expiry, revocation
// ---------------------------------------------------------------------------

it('unions permissions across several roles held at once', function () {
    ['module' => $module, 'perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $second = Permission::create(['name' => 'roster.edit', 'module_id' => $module->id]);

    $roleA = roleWith('location', $perm, 'role_a');
    $roleB = Role::create(['account_id' => null, 'key' => 'role_b', 'name' => 'Role B',
        'scope_level' => 'location', 'is_system' => true]);
    $roleB->permissions()->attach($second->id);

    $user = makeUser('Multi Role');
    grant($user, $roleA, $account->id, $loc->id);
    grant($user, $roleB, $account->id, $loc->id);

    expect($user->roleAssignments()->active()->count())->toBe(2)
        ->and($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue()
        ->and($user->hasPermission('roster.edit', $account->id, $loc->id))->toBeTrue();
});

it('drops a temporary grant once it expires', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $user = makeUser('Temp Elevated');

    grant($user, roleWith('location', $perm), $account->id, $loc->id,
        validUntil: now()->addHour()->toDateTimeString());
    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue();

    $this->travel(2)->hours();

    // No cache to flush: grants are read live precisely so this cannot go stale.
    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeFalse();
});

it('revokes without deleting, and allows a later re-grant', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $user = makeUser('Revoke Test');
    $role = roleWith('location', $perm);

    $assignment = grant($user, $role, $account->id, $loc->id);
    app(RevokeRole::class)($assignment);

    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeFalse()
        ->and(UserRoleAssignment::count())->toBe(1);          // history kept

    grant($user, $role, $account->id, $loc->id);

    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue()
        ->and(UserRoleAssignment::count())->toBe(2);          // both rows retained
});

// ---------------------------------------------------------------------------
// Grant validation
// ---------------------------------------------------------------------------

it('rejects a duplicate grant at the same scope', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $user = makeUser('Dupe Test');
    $role = roleWith('location', $perm);

    grant($user, $role, $account->id, $loc->id);
    grant($user, $role, $account->id, $loc->id);
})->throws(ValidationException::class);

it('rejects a location role granted without a location', function () {
    ['perm' => $perm, 'account' => $account] = scenario();

    grant(makeUser('Bad Scope'), roleWith('location', $perm), $account->id);
})->throws(ValidationException::class);

it('rejects an account role granted with a location', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();

    grant(makeUser('Bad Account'), roleWith('account', $perm), $account->id, $loc->id);
})->throws(ValidationException::class);

it('rejects any grant without an account', function () {
    ['perm' => $perm] = scenario();

    grant(makeUser('No Account'), roleWith('account', $perm));
})->throws(ValidationException::class);

it('denies a permission nobody granted', function () {
    ['account' => $account] = scenario();

    expect(makeUser('Nobody Special')->hasPermission('roster.publish', $account->id))->toBeFalse();
});

// ---------------------------------------------------------------------------
// The Gate is the public entry point
// ---------------------------------------------------------------------------

it('answers through the Gate as well as the resolver', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc, 'location2' => $loc2] = scenario();
    $user = makeUser('Gate User');

    grant($user, roleWith('location', $perm), $account->id, $loc->id);

    expect($user->can('roster.publish', [$account->id, $loc->id]))->toBeTrue()
        ->and($user->can('roster.publish', [$account->id, $loc2->id]))->toBeFalse();
});

// ---------------------------------------------------------------------------
// Guard rail
// ---------------------------------------------------------------------------

it('never calls Spatie methods that would bypass scope or delete the audit trail', function () {
    // assignRole/removeRole/syncRoles write the pivot without location, scope
    // or audit columns, and removeRole DETACHES -- deleting revocation history.
    // hasRole/hasPermissionTo/hasAnyRole skip the Gate, so they skip the module
    // boundary and the location check. Grants go through GrantRole/RevokeRole.
    $banned = ['assignRole', 'removeRole', 'syncRoles', 'hasRole', 'hasAnyRole', 'hasPermissionTo'];

    $offenders = [];

    foreach (['app', 'database/seeders'] as $dir) {
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(base_path($dir)));

        foreach ($files as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }

            $source = file_get_contents($file->getPathname());

            foreach ($banned as $method) {
                // Role::hasPermissionTo is the one legitimate use: it reads the
                // role's own permissions and is how the resolver asks Spatie.
                if (preg_match('/->'.$method.'\(/', $source)
                    && ! str_contains($file->getPathname(), 'PermissionResolver.php')) {
                    $offenders[] = str_replace(base_path().'/', '', $file->getPathname())." uses ->{$method}()";
                }
            }
        }
    }

    expect($offenders)->toBe([]);
});
