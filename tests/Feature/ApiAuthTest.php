<?php

use App\Domain\Identity\Models\Account;
use App\Domain\Identity\Models\Location;
use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Models\Module;
use App\Domain\Rbac\Models\Permission;
use App\Domain\Rbac\Models\Role;
use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Domain\Rbac\Support\RbacAudit;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

function makePerson(string $email): User
{
    return User::create([
        'first_name' => 'Test', 'last_name' => 'Person', 'uuid' => (string) Str::uuid(),
        'email' => $email, 'mobile' => '+614'.random_int(10000000, 99999999),
        'password' => Hash::make('password'),
    ]);
}

function rbacWorld(): array
{
    $system = Module::create(['key' => 'system', 'name' => 'System', 'is_core' => true]);
    $travel = Module::create(['key' => 'travel', 'name' => 'Travel']);

    $audit = Permission::create(['name' => 'system.audit_view', 'module_id' => $system->id]);
    $manage = Permission::create(['name' => 'system.integration_manage', 'module_id' => $system->id]);
    $users = Permission::create(['name' => 'system.user_manage', 'module_id' => $system->id]);
    $book = Permission::create(['name' => 'travel.book', 'module_id' => $travel->id]);

    $account = Account::create(['name' => 'Acme', 'slug' => 'acme']);
    Location::create(['account_id' => $account->id, 'name' => 'Village', 'slug' => 'village']);
    $account->modules()->attach($system->id, ['is_enabled' => true]);
    $account->modules()->attach($travel->id, ['is_enabled' => true]);

    $admin = Role::create(['key' => 'admin', 'name' => 'Administrator', 'scope_level' => 'account', 'is_system' => true]);
    $admin->permissions()->attach([$audit->id, $manage->id, $users->id, $book->id]);

    $worker = Role::create(['key' => 'worker', 'name' => 'Worker', 'scope_level' => 'account', 'is_system' => true]);
    $worker->permissions()->attach($book->id);

    // A second tenant, to prove an account-level grant cannot reach it.
    $other = Account::create(['name' => 'Rio', 'slug' => 'rio']);
    $other->modules()->attach($system->id, ['is_enabled' => true]);
    $other->modules()->attach($travel->id, ['is_enabled' => true]);

    return compact('account', 'other', 'admin', 'worker', 'travel');
}

/** An account-scoped grant, written directly as the fixtures above do. */
function holds(User $user, Role $role, Account $account): UserRoleAssignment
{
    return UserRoleAssignment::create([
        'model_id' => $user->id, 'model_type' => $user::class, 'role_id' => $role->id,
        'scope_level' => 'account', 'account_id' => $account->id, 'valid_from' => now(),
    ]);
}

it('rejects an unauthenticated request', function () {
    rbacWorld();

    $this->getJson('/api/v1/users')->assertStatus(401);
});

it('rejects a signed-in user who lacks the permission', function () {
    ['account' => $account, 'worker' => $worker, 'travel' => $travel] = rbacWorld();
    $user = makePerson('worker@example.com');

    UserRoleAssignment::create([
        'model_id' => $user->id, 'model_type' => $user::class, 'role_id' => $worker->id,
        'scope_level' => 'account', 'account_id' => $account->id, 'valid_from' => now(),
    ]);

    $this->actingAs($user)->getJson('/api/v1/users')->assertStatus(403);
    $this->actingAs($user)
        ->putJson("/api/v1/accounts/{$account->id}/modules/{$travel->id}", ['is_enabled' => false])
        ->assertStatus(403);
});

it('allows a user who holds the permission', function () {
    ['account' => $account, 'admin' => $admin] = rbacWorld();
    $user = makePerson('admin@example.com');

    UserRoleAssignment::create([
        'model_id' => $user->id, 'model_type' => $user::class, 'role_id' => $admin->id,
        'scope_level' => 'account', 'account_id' => $account->id, 'valid_from' => now(),
    ]);

    $this->actingAs($user)->getJson('/api/v1/users')->assertOk();
    $this->actingAs($user)->getJson('/api/v1/audit')->assertOk();
});

it('returns the signed-in profile with roles and permissions', function () {
    ['account' => $account, 'admin' => $admin] = rbacWorld();
    $user = makePerson('admin@example.com');
    UserRoleAssignment::create([
        'model_id' => $user->id, 'model_type' => $user::class, 'role_id' => $admin->id,
        'scope_level' => 'account', 'account_id' => $account->id, 'valid_from' => now(),
    ]);

    $this->actingAs($user)->getJson('/api/v1/me')
        ->assertOk()
        ->assertJsonPath('data.user.email', 'admin@example.com')
        ->assertJsonPath('data.roles.0.role', 'Administrator')
        ->assertJsonFragment(['system.audit_view']);
});

it('records an audit entry when a role is granted and revoked', function () {
    ['account' => $account, 'admin' => $admin, 'worker' => $worker] = rbacWorld();
    $actor = makePerson('actor@example.com');
    $target = makePerson('target@example.com');

    UserRoleAssignment::create([
        'model_id' => $actor->id, 'model_type' => $actor::class, 'role_id' => $admin->id,
        'scope_level' => 'account', 'account_id' => $account->id, 'valid_from' => now(),
    ]);

    $this->actingAs($actor)
        ->postJson("/api/v1/users/{$target->id}/assignments", [
            'role_id' => $worker->id, 'account_id' => $account->id, 'reason' => 'covering leave',
        ])->assertStatus(201);

    $granted = RbacAudit::query()->where('event', 'role.granted')->first();

    expect($granted)->not->toBeNull()
        ->and($granted->causer_id)->toBe($actor->id)
        ->and($granted->properties['reason'])->toBe('covering leave');

    $assignment = UserRoleAssignment::where('model_id', $target->id)->firstOrFail();
    $this->actingAs($actor)->deleteJson("/api/v1/assignments/{$assignment->id}")->assertOk();

    expect(RbacAudit::query()->where('event', 'role.revoked')->exists())->toBeTrue();
});

it('records an audit entry when a module is toggled', function () {
    ['account' => $account, 'admin' => $admin, 'travel' => $travel] = rbacWorld();
    $actor = makePerson('actor@example.com');
    UserRoleAssignment::create([
        'model_id' => $actor->id, 'model_type' => $actor::class, 'role_id' => $admin->id,
        'scope_level' => 'account', 'account_id' => $account->id, 'valid_from' => now(),
    ]);

    $this->actingAs($actor)
        ->putJson("/api/v1/accounts/{$account->id}/modules/{$travel->id}", ['is_enabled' => false])
        ->assertOk();

    $entry = RbacAudit::query()->where('event', 'module.disabled')->first();

    expect($entry)->not->toBeNull()
        ->and($entry->properties['module'])->toBe('travel')
        ->and($entry->properties['account_id'])->toBe($account->id);
});

it('creates a user with no roles and an unusable password', function () {
    ['account' => $account, 'admin' => $admin] = rbacWorld();
    $actor = makePerson('actor@example.com');
    UserRoleAssignment::create([
        'model_id' => $actor->id, 'model_type' => $actor::class, 'role_id' => $admin->id,
        'scope_level' => 'account', 'account_id' => $account->id, 'valid_from' => now(),
    ]);

    $this->actingAs($actor)->postJson('/api/v1/users', [
        'first_name' => 'Priya', 'last_name' => 'Raman',
        'email' => 'priya@example.com', 'account_id' => $account->id,
    ])->assertStatus(201)->assertJsonPath('data.name', 'Priya Raman');

    $created = User::where('email', 'priya@example.com')->firstOrFail();

    // Existing must not confer access.
    expect($created->roleAssignments()->count())->toBe(0)
        // The random secret must not match anything a person could type.
        ->and(Hash::check('password', $created->password))->toBeFalse()
        ->and(RbacAudit::query()->where('event', 'user.created')->exists())->toBeTrue();
});

it('refuses to create a user without the manage permission', function () {
    ['account' => $account, 'worker' => $worker] = rbacWorld();
    $user = makePerson('worker@example.com');
    UserRoleAssignment::create([
        'model_id' => $user->id, 'model_type' => $user::class, 'role_id' => $worker->id,
        'scope_level' => 'account', 'account_id' => $account->id, 'valid_from' => now(),
    ]);

    $this->actingAs($user)->postJson('/api/v1/users', [
        'first_name' => 'Nope', 'last_name' => 'Nope', 'email' => 'nope@example.com',
    ])->assertStatus(403);

    expect(User::where('email', 'nope@example.com')->exists())->toBeFalse();
});

it('rejects a duplicate email', function () {
    ['account' => $account, 'admin' => $admin] = rbacWorld();
    $actor = makePerson('actor@example.com');
    UserRoleAssignment::create([
        'model_id' => $actor->id, 'model_type' => $actor::class, 'role_id' => $admin->id,
        'scope_level' => 'account', 'account_id' => $account->id, 'valid_from' => now(),
    ]);

    $this->actingAs($actor)->postJson('/api/v1/users', [
        'first_name' => 'Dupe', 'last_name' => 'Test', 'email' => 'actor@example.com',
    ])->assertStatus(422)->assertJsonValidationErrors('email');
});

// ---- Who may add personnel -------------------------------------------------
//
// system.user_manage is answered for one account: a grant in Acme adds,
// grants and revokes in Acme only. Operational roles never carry it.

it('adds a person to the account the grant covers', function () {
    ['account' => $account, 'admin' => $admin] = rbacWorld();
    $actor = makePerson('account.admin@example.com');
    holds($actor, $admin, $account);

    $this->actingAs($actor)->postJson('/api/v1/users', [
        'first_name' => 'Priya', 'last_name' => 'Raman',
        'email' => 'priya@example.com', 'account_id' => $account->id,
    ])->assertStatus(201);

    $created = User::where('email', 'priya@example.com')->firstOrFail();

    expect($created->accounts()->pluck('accounts.id')->all())->toBe([$account->id])
        ->and($created->roleAssignments()->count())->toBe(0);
});

it('places a person in the account in scope when none is given', function () {
    ['account' => $account, 'admin' => $admin] = rbacWorld();
    $actor = makePerson('account.admin@example.com');
    holds($actor, $admin, $account);

    $this->actingAs($actor)->postJson('/api/v1/users', [
        'first_name' => 'No', 'last_name' => 'Account', 'email' => 'noaccount@example.com',
    ])->assertStatus(201);

    expect(User::where('email', 'noaccount@example.com')->firstOrFail()
        ->accounts()->pluck('accounts.id')->all())->toBe([$account->id]);
});

it('refuses adding a person to an account the grant does not cover', function () {
    ['account' => $account, 'other' => $other, 'admin' => $admin] = rbacWorld();
    $actor = makePerson('account.admin@example.com');
    holds($actor, $admin, $account);

    $this->actingAs($actor)->postJson('/api/v1/users', [
        'first_name' => 'Cross', 'last_name' => 'Tenant',
        'email' => 'cross@example.com', 'account_id' => $other->id,
    ])->assertStatus(403);

    $this->actingAs($actor)->withHeader('X-Account-Id', (string) $other->id)
        ->postJson('/api/v1/users', [
            'first_name' => 'Cross', 'last_name' => 'Tenant', 'email' => 'cross@example.com',
        ])->assertStatus(403);

    expect(User::where('email', 'cross@example.com')->exists())->toBeFalse();
});

it('refuses an operational role adding a person, even inside its own account', function () {
    ['account' => $account, 'worker' => $worker] = rbacWorld();
    $actor = makePerson('coordinator@example.com');
    holds($actor, $worker, $account);

    $this->actingAs($actor)->postJson('/api/v1/users', [
        'first_name' => 'Nope', 'last_name' => 'Nope',
        'email' => 'nope@example.com', 'account_id' => $account->id,
    ])->assertStatus(403);

    expect(User::where('email', 'nope@example.com')->exists())->toBeFalse();
});

it('lets a super administrator add a person to any account', function () {
    ['other' => $other] = rbacWorld();
    $root = makePerson('root@example.com');
    $root->forceFill(['is_admin' => true])->save();

    $this->actingAs($root)->postJson('/api/v1/users', [
        'first_name' => 'Anywhere', 'last_name' => 'Person',
        'email' => 'anywhere@example.com', 'account_id' => $other->id,
    ])->assertStatus(201);

    expect(User::where('email', 'anywhere@example.com')->firstOrFail()
        ->accounts()->pluck('accounts.id')->all())->toBe([$other->id]);
});

it("grants roles in the caller's own account but not another's", function () {
    ['account' => $account, 'other' => $other, 'admin' => $admin, 'worker' => $worker] = rbacWorld();
    $actor = makePerson('account.admin@example.com');
    holds($actor, $admin, $account);
    $target = makePerson('target@example.com');

    $this->actingAs($actor)->postJson("/api/v1/users/{$target->id}/assignments", [
        'role_id' => $worker->id, 'account_id' => $account->id,
    ])->assertStatus(201);

    $this->actingAs($actor)->postJson("/api/v1/users/{$target->id}/assignments", [
        'role_id' => $worker->id, 'account_id' => $other->id,
    ])->assertStatus(403);

    expect($target->roleAssignments()->where('account_id', $other->id)->exists())->toBeFalse();
});

it('refuses revoking access in an account the grant does not cover', function () {
    ['account' => $account, 'other' => $other, 'admin' => $admin, 'worker' => $worker] = rbacWorld();
    $actor = makePerson('account.admin@example.com');
    holds($actor, $admin, $account);
    $foreign = holds(makePerson('rio.worker@example.com'), $worker, $other);

    // The request resolves to the actor's own account, where they do hold the
    // permission -- the assignment's account is what has to be checked.
    $this->actingAs($actor)->deleteJson("/api/v1/assignments/{$foreign->id}")->assertStatus(403);

    expect($foreign->fresh()->revoked_at)->toBeNull();

    $own = holds(makePerson('acme.worker@example.com'), $worker, $account);
    $this->actingAs($actor)->deleteJson("/api/v1/assignments/{$own->id}")->assertOk();

    expect($own->fresh()->revoked_at)->not->toBeNull();
});
