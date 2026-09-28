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
use App\Domain\Rbac\Services\PermissionCatalog;
use App\Domain\Rbac\Support\PermissionScope;
use App\Domain\Rbac\Support\RbacAudit;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
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
    ?string $validUntil = null, ?string $reason = null): UserRoleAssignment
{
    return app(GrantRole::class)(new GrantRoleData(
        user: $user, role: $role, accountId: $accountId,
        locationId: $locationId, reason: $reason, validUntil: $validUntil,
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
    app(PermissionCatalog::class)->flushModule('roster', $account->id);

    expect($user->hasPermission('roster.publish', $account->id))->toBeFalse();
});

it('denies a super admin a module the account has not bought', function () {
    ['module' => $module, 'account' => $account] = scenario();
    $user = makeUser('Glenda Global', superAdmin: true);

    $account->modules()->updateExistingPivot($module->id, ['is_enabled' => false]);
    app(PermissionCatalog::class)->flushModule('roster', $account->id);

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
        validUntil: now()->addHour()->toDateTimeString(), reason: 'covering the night shift');
    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue();

    $this->travel(2)->hours();

    // No cache to flush: grants are read live precisely so this cannot go stale.
    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeFalse();
});

it('refuses a temporary grant without a reason', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $user = makeUser('No Reason');
    $role = roleWith('location', $perm);
    $until = now()->addHour()->toDateTimeString();

    expect(fn () => grant($user, $role, $account->id, $loc->id, validUntil: $until))
        ->toThrow(ValidationException::class, 'A temporary grant needs a reason.')
        ->and(fn () => grant($user, $role, $account->id, $loc->id, validUntil: $until, reason: '   '))
        ->toThrow(ValidationException::class, 'A temporary grant needs a reason.')
        ->and(UserRoleAssignment::count())->toBe(0);
});

it('refuses a temporary grant longer than the configured maximum', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $user = makeUser('Too Long');
    $role = roleWith('location', $perm);
    config(['rbac.temporary_grant_max_days' => 30]);

    expect(fn () => grant($user, $role, $account->id, $loc->id,
        validUntil: now()->addDays(31)->toDateTimeString(), reason: 'project cover'))
        ->toThrow(ValidationException::class, 'A temporary grant can last at most 30 days.')
        ->and(UserRoleAssignment::count())->toBe(0);

    grant($user, $role, $account->id, $loc->id,
        validUntil: now()->addDays(30)->toDateTimeString(), reason: 'project cover');

    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue();
});

it('still allows a permanent grant without a reason', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $user = makeUser('Permanent Grant');

    grant($user, roleWith('location', $perm), $account->id, $loc->id);

    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue();
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

it('rejects a location that belongs to another account', function () {
    ['perm' => $perm, 'account' => $account, 'other' => $other] = scenario();
    $foreign = Location::create(['account_id' => $other->id, 'name' => 'Foreign', 'slug' => 'foreign']);
    $user = makeUser('Cross Tenant');

    expect(fn () => grant($user, roleWith('location', $perm), $account->id, $foreign->id))
        ->toThrow(ValidationException::class)
        ->and(UserRoleAssignment::count())->toBe(0)
        ->and($user->hasPermission('roster.publish', $account->id, $foreign->id))->toBeFalse();
});

it('rejects a role owned by another account', function () {
    ['perm' => $perm, 'account' => $account, 'other' => $other] = scenario();
    $role = Role::create([
        'account_id' => $other->id, 'key' => 'other_only', 'name' => 'Other Only',
        'scope_level' => 'account', 'is_system' => false,
    ]);
    $role->permissions()->attach($perm->id);

    expect(fn () => grant(makeUser('Foreign Role'), $role, $account->id))
        ->toThrow(ValidationException::class)
        ->and(UserRoleAssignment::count())->toBe(0);
});

it("grants an account's own role inside that account", function () {
    ['perm' => $perm, 'account' => $account] = scenario();
    $role = Role::create([
        'account_id' => $account->id, 'key' => 'acme_only', 'name' => 'Acme Only',
        'scope_level' => 'account', 'is_system' => false,
    ]);
    $role->permissions()->attach($perm->id);
    $user = makeUser('Own Role');

    grant($user, $role, $account->id);

    expect($user->hasPermission('roster.publish', $account->id))->toBeTrue();
});

it('denies a permission nobody granted', function () {
    ['account' => $account] = scenario();

    expect(makeUser('Nobody Special')->hasPermission('roster.publish', $account->id))->toBeFalse();
});

// ---------------------------------------------------------------------------
// Spatie's own API is the entry point
// ---------------------------------------------------------------------------
//
// can(), hasPermissionTo() and the permission: middleware all answer for the
// scope ResolveTenant sets. These set it the same way and ask through each
// door, including the cases Spatie alone would get wrong.

afterEach(fn () => app(PermissionScope::class)->set(null));

it('registers Spatie\'s Gate hook', function () {
    expect(config('permission.register_permission_check_method'))->toBeTrue();
});

it('answers can() for the location in scope', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc, 'location2' => $loc2] = scenario();
    $user = makeUser('Gate User');
    grant($user, roleWith('location', $perm), $account->id, $loc->id);

    app(PermissionScope::class)->set($account->id, $loc->id);
    expect($user->can('roster.publish'))->toBeTrue()
        ->and($user->hasPermissionTo('roster.publish'))->toBeTrue();

    app(PermissionScope::class)->set($account->id, $loc2->id);
    expect($user->can('roster.publish'))->toBeFalse()
        ->and($user->hasPermissionTo('roster.publish'))->toBeFalse();
});

it('does not answer can() for another account', function () {
    ['perm' => $perm, 'account' => $account, 'other' => $other] = scenario();
    $user = makeUser('Gate Account');
    grant($user, roleWith('account', $perm), $account->id);

    app(PermissionScope::class)->set($other->id);

    expect($user->can('roster.publish'))->toBeFalse();
});

it('denies can() once the grant is revoked, on the same model instance', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $user = makeUser('Gate Revoked');
    $assignment = grant($user, roleWith('location', $perm), $account->id, $loc->id);
    app(PermissionScope::class)->set($account->id, $loc->id);

    expect($user->can('roster.publish'))->toBeTrue();     // loads Spatie's roles relation

    app(RevokeRole::class)($assignment);

    expect($user->can('roster.publish'))->toBeFalse();    // ...which must not be reused
});

it('denies can() once a temporary grant expires', function () {
    ['perm' => $perm, 'account' => $account] = scenario();
    $user = makeUser('Gate Expiry');
    grant($user, roleWith('account', $perm), $account->id, validUntil: now()->addHour()->toDateTimeString(), reason: 'covering leave');
    app(PermissionScope::class)->set($account->id);

    expect($user->can('roster.publish'))->toBeTrue();
    $this->travel(2)->hours();
    expect($user->can('roster.publish'))->toBeFalse();
});

it('denies can() when the module is disabled, even for a super admin', function () {
    ['account' => $account, 'module' => $module, 'perm' => $perm] = scenario();
    $user = makeUser('Gate Module');
    grant($user, roleWith('account', $perm), $account->id);
    $admin = makeUser('Gate Admin', superAdmin: true);

    $account->modules()->updateExistingPivot($module->id, ['is_enabled' => false]);
    app(PermissionCatalog::class)->flushModule('roster', $account->id);
    app(PermissionScope::class)->set($account->id);

    expect($user->can('roster.publish'))->toBeFalse()
        ->and($admin->can('roster.publish'))->toBeFalse();
});

it('treats an unknown permission as a plain no through can()', function () {
    ['account' => $account] = scenario();
    app(PermissionScope::class)->set($account->id);

    expect(makeUser('Gate Admin', superAdmin: true)->can('roster.invented'))->toBeFalse();
});

it('leaves non-permission abilities to ordinary Laravel gates', function () {
    Gate::define('edit-profile', fn () => true);

    expect(makeUser('Plain Gate')->can('edit-profile'))->toBeTrue();
});

it('restores the request scope after asking about another one', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc, 'other' => $other] = scenario();
    $user = makeUser('Scope Restore');
    grant($user, roleWith('location', $perm), $account->id, $loc->id);
    $scope = app(PermissionScope::class);
    $scope->set($other->id);

    expect($user->hasPermission('roster.publish', $account->id, $loc->id))->toBeTrue()
        ->and($scope->accountId())->toBe($other->id)
        ->and($scope->locationId())->toBeNull()
        ->and($user->can('roster.publish'))->toBeFalse();
});

it('guards a route with Spatie\'s permission middleware, scoped by the tenant middleware', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc, 'location2' => $loc2] = scenario();
    $user = makeUser('Route User');
    grant($user, roleWith('location', $perm), $account->id, $loc->id);

    Route::middleware(['auth:sanctum', 'tenant', 'permission:roster.publish'])
        ->get('/_test/publish', fn () => response()->json(['ok' => true]));

    $this->actingAs($user)
        ->getJson("/_test/publish?account_id={$account->id}&location_id={$loc->id}")->assertOk();
    $this->actingAs($user)
        ->getJson("/_test/publish?account_id={$account->id}&location_id={$loc2->id}")->assertForbidden();
});

// ---------------------------------------------------------------------------
// Guard rail
// ---------------------------------------------------------------------------

it('never calls Spatie methods that would bypass scope or delete the audit trail', function () {
    // Reads are Spatie's and are scope-safe (see User::roles/hasPermissionTo).
    // Writes are not: assignRole/removeRole/syncRoles write the pivot without
    // location, scope or audit columns, and removeRole DETACHES -- deleting
    // revocation history. Grants go through GrantRole/RevokeRole.
    $banned = ['assignRole', 'removeRole', 'syncRoles'];

    $offenders = [];

    foreach (['app', 'database/seeders'] as $dir) {
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(base_path($dir)));

        foreach ($files as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }

            $source = file_get_contents($file->getPathname());

            foreach ($banned as $method) {
                if (preg_match('/->'.$method.'\(/', $source)) {
                    $offenders[] = str_replace(base_path().'/', '', $file->getPathname())." uses ->{$method}()";
                }
            }
        }
    }

    expect($offenders)->toBe([]);
});

// ---------------------------------------------------------------------------
// Expiry audit: rbac:record-expiries
// ---------------------------------------------------------------------------

it('records one role.expired entry per expired grant, dated at valid_until', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $user = makeUser('Temp Cover');
    $until = now()->addHour()->startOfSecond();

    $assignment = grant($user, roleWith('location', $perm), $account->id, $loc->id,
        validUntil: $until->toDateTimeString(), reason: 'night cover');

    $this->artisan('rbac:record-expiries')->assertSuccessful();
    expect(RbacAudit::query()->where('event', 'role.expired')->count())->toBe(0);   // not expired yet

    $this->travel(2)->hours();
    $this->artisan('rbac:record-expiries')->assertSuccessful();
    $this->artisan('rbac:record-expiries')->assertSuccessful();   // a second run adds nothing

    $entries = RbacAudit::query()->where('event', 'role.expired')->get();

    expect($entries)->toHaveCount(1)
        ->and($entries[0]->subject_id)->toBe($assignment->id)
        ->and($entries[0]->causer_id)->toBeNull()
        ->and($entries[0]->properties['account_id'])->toBe($account->id)
        ->and($entries[0]->properties['reason'])->toBe('night cover')
        ->and($entries[0]->created_at->equalTo($until))->toBeTrue()
        ->and($assignment->fresh()->expiry_recorded_at)->not->toBeNull();
});

it('does not record an expiry for a grant revoked before it ran out', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    $user = makeUser('Revoked Early');

    $assignment = grant($user, roleWith('location', $perm), $account->id, $loc->id,
        validUntil: now()->addHour()->toDateTimeString(), reason: 'short cover');
    app(RevokeRole::class)($assignment);

    $this->travel(2)->hours();
    $this->artisan('rbac:record-expiries')->assertSuccessful();

    expect(RbacAudit::query()->where('event', 'role.expired')->exists())->toBeFalse();
});

it('ignores permanent grants', function () {
    ['perm' => $perm, 'account' => $account, 'location' => $loc] = scenario();
    grant(makeUser('Permanent Holder'), roleWith('location', $perm), $account->id, $loc->id);

    $this->travel(1)->years();
    $this->artisan('rbac:record-expiries')->assertSuccessful();

    expect(RbacAudit::query()->where('event', 'role.expired')->exists())->toBeFalse();
});

it('schedules rbac:record-expiries every five minutes', function () {
    $event = collect(app(Schedule::class)->events())
        ->first(fn ($e) => str_contains($e->command ?? '', 'rbac:record-expiries'));

    expect($event)->not->toBeNull()
        ->and($event->expression)->toBe('*/5 * * * *');
});
