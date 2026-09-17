<?php

use App\Domain\Identity\Models\{Account, Location, User};
use App\Domain\Rbac\Models\{Module, Permission, Role, UserRoleAssignment};
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

    $audit  = Permission::create(['name' => 'system.audit_view', 'module_id' => $system->id]);
    $manage = Permission::create(['name' => 'system.integration_manage', 'module_id' => $system->id]);
    $book   = Permission::create(['name' => 'travel.book', 'module_id' => $travel->id]);

    $account = Account::create(['name' => 'Acme', 'slug' => 'acme']);
    Location::create(['account_id' => $account->id, 'name' => 'Village', 'slug' => 'village']);
    $account->modules()->attach($system->id, ['is_enabled' => true]);
    $account->modules()->attach($travel->id, ['is_enabled' => true]);

    $admin = Role::create(['key' => 'admin', 'name' => 'Administrator', 'scope_level' => 'global', 'is_system' => true]);
    $admin->permissions()->attach([$audit->id, $manage->id, $book->id]);

    $worker = Role::create(['key' => 'worker', 'name' => 'Worker', 'scope_level' => 'account', 'is_system' => true]);
    $worker->permissions()->attach($book->id);

    return compact('account', 'admin', 'worker', 'travel');
}

it('rejects an unauthenticated request', function () {
    rbacWorld();

    $this->getJson('/api/v1/users')->assertStatus(401);
});

it('rejects a signed-in user who lacks the permission', function () {
    ['account' => $account, 'worker' => $worker, 'travel' => $travel] = rbacWorld();
    $user = makePerson('worker@example.com');

    UserRoleAssignment::create([
        'user_id' => $user->id, 'role_id' => $worker->id, 'scope_level' => 'account',
        'account_id' => $account->id, 'valid_from' => now(),
    ]);

    $this->actingAs($user)->getJson('/api/v1/users')->assertStatus(403);
    $this->actingAs($user)
        ->putJson("/api/v1/accounts/{$account->id}/modules/{$travel->id}", ['is_enabled' => false])
        ->assertStatus(403);
});

it('allows a user who holds the permission', function () {
    ['admin' => $admin] = rbacWorld();
    $user = makePerson('admin@example.com');

    UserRoleAssignment::create([
        'user_id' => $user->id, 'role_id' => $admin->id, 'scope_level' => 'global', 'valid_from' => now(),
    ]);

    $this->actingAs($user)->getJson('/api/v1/users')->assertOk();
    $this->actingAs($user)->getJson('/api/v1/audit')->assertOk();
});

it('returns the signed-in profile with roles and permissions', function () {
    ['admin' => $admin] = rbacWorld();
    $user = makePerson('admin@example.com');
    UserRoleAssignment::create([
        'user_id' => $user->id, 'role_id' => $admin->id, 'scope_level' => 'global', 'valid_from' => now(),
    ]);

    $this->actingAs($user)->getJson('/api/v1/me')
        ->assertOk()
        ->assertJsonPath('user.email', 'admin@example.com')
        ->assertJsonPath('roles.0.role', 'Administrator')
        ->assertJsonFragment(['system.audit_view']);
});

it('records an audit entry when a role is granted and revoked', function () {
    ['account' => $account, 'admin' => $admin, 'worker' => $worker] = rbacWorld();
    $actor = makePerson('actor@example.com');
    $target = makePerson('target@example.com');

    UserRoleAssignment::create([
        'user_id' => $actor->id, 'role_id' => $admin->id, 'scope_level' => 'global', 'valid_from' => now(),
    ]);

    $this->actingAs($actor)
        ->postJson("/api/v1/users/{$target->id}/assignments", [
            'role_id' => $worker->id, 'account_id' => $account->id, 'reason' => 'covering leave',
        ])->assertStatus(201);

    $granted = RbacAudit::query()->where('event', 'role.granted')->first();

    expect($granted)->not->toBeNull()
        ->and($granted->causer_id)->toBe($actor->id)
        ->and($granted->properties['reason'])->toBe('covering leave');

    $assignment = UserRoleAssignment::where('user_id', $target->id)->firstOrFail();
    $this->actingAs($actor)->deleteJson("/api/v1/assignments/{$assignment->id}")->assertOk();

    expect(RbacAudit::query()->where('event', 'role.revoked')->exists())->toBeTrue();
});

it('records an audit entry when a module is toggled', function () {
    ['account' => $account, 'admin' => $admin, 'travel' => $travel] = rbacWorld();
    $actor = makePerson('actor@example.com');
    UserRoleAssignment::create([
        'user_id' => $actor->id, 'role_id' => $admin->id, 'scope_level' => 'global', 'valid_from' => now(),
    ]);

    $this->actingAs($actor)
        ->putJson("/api/v1/accounts/{$account->id}/modules/{$travel->id}", ['is_enabled' => false])
        ->assertOk();

    $entry = RbacAudit::query()->where('event', 'module.disabled')->first();

    expect($entry)->not->toBeNull()
        ->and($entry->properties['module'])->toBe('travel')
        ->and($entry->properties['account_id'])->toBe($account->id);
});
