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

/*
| Account and location administration.
|
| Both are platform administration: system.account_manage and
| system.location_manage are carried by no role, so only a super administrator
| gets through. Reads are open to members of the account, and GET /accounts
| never shows a client another client's name.
*/

function tenantWorld(): array
{
    $system = Module::create(['key' => 'system', 'name' => 'System', 'is_core' => true]);
    $roster = Module::create(['key' => 'roster', 'name' => 'Roster']);

    foreach (['system.audit_view', 'system.account_manage', 'system.location_manage', 'system.user_manage'] as $name) {
        Permission::create(['name' => $name, 'module_id' => $system->id]);
    }

    $acme = Account::create(['name' => 'Acme', 'slug' => 'acme']);
    $rio = Account::create(['name' => 'Rio', 'slug' => 'rio']);

    foreach ([$acme, $rio] as $account) {
        $account->modules()->attach($system->id, ['is_enabled' => true]);
    }

    $village = Location::create(['account_id' => $acme->id, 'name' => 'Village', 'slug' => 'village']);
    $camp = Location::create(['account_id' => $rio->id, 'name' => 'Camp', 'slug' => 'camp']);

    // The most an account-level role holds today: user and audit rights, but
    // nothing that reaches accounts or locations.
    $admin = Role::create(['key' => 'admin', 'name' => 'Administrator', 'scope_level' => 'account', 'is_system' => true]);
    $admin->permissions()->attach(Permission::whereIn('name', ['system.audit_view', 'system.user_manage'])->pluck('id'));

    $local = Role::create(['key' => 'local', 'name' => 'Local', 'scope_level' => 'location', 'is_system' => true]);
    $local->permissions()->attach(Permission::where('name', 'system.audit_view')->value('id'));

    return compact('system', 'roster', 'acme', 'rio', 'village', 'camp', 'admin', 'local');
}

function tenantPerson(string $email, bool $superAdmin = false): User
{
    $user = User::create([
        'first_name' => 'Test', 'last_name' => 'Person', 'uuid' => (string) Str::uuid(),
        'email' => $email, 'password' => Hash::make('password'),
    ]);

    if ($superAdmin) {
        $user->forceFill(['is_admin' => true])->save();
    }

    return $user;
}

function grantIn(User $user, Role $role, Account $account, ?Location $location = null): UserRoleAssignment
{
    return UserRoleAssignment::create([
        'model_id' => $user->id, 'model_type' => $user::class, 'role_id' => $role->id,
        'scope_level' => $role->scope_level, 'account_id' => $account->id,
        'location_id' => $location?->id, 'valid_from' => now(),
    ]);
}

// ---- Listing ---------------------------------------------------------------

it('lists only the accounts a person holds a grant in', function () {
    ['acme' => $acme, 'admin' => $admin] = tenantWorld();
    $user = tenantPerson('member@example.com');
    grantIn($user, $admin, $acme);

    $this->actingAs($user)->getJson('/api/v1/accounts')
        ->assertOk()
        ->assertJsonCount(1, 'data')
        ->assertJsonPath('data.0.name', 'Acme')
        ->assertJsonMissing(['name' => 'Rio']);
});

it('lists every account for a super administrator', function () {
    tenantWorld();

    $this->actingAs(tenantPerson('root@example.com', superAdmin: true))
        ->getJson('/api/v1/accounts')
        ->assertOk()
        ->assertJsonCount(2, 'data');
});

it("refuses reading another account's locations", function () {
    ['acme' => $acme, 'rio' => $rio, 'admin' => $admin] = tenantWorld();
    $user = tenantPerson('member@example.com');
    grantIn($user, $admin, $acme);

    $this->actingAs($user)->getJson("/api/v1/accounts/{$acme->id}/locations")
        ->assertOk()->assertJsonPath('data.0.name', 'Village');
    $this->actingAs($user)->getJson("/api/v1/accounts/{$rio->id}/locations")->assertStatus(403);
    $this->actingAs($user)->getJson("/api/v1/accounts/{$rio->id}")->assertStatus(403);
});

// ---- Accounts --------------------------------------------------------------

it('lets a super administrator create an account with only core modules on', function () {
    ['system' => $system, 'roster' => $roster] = tenantWorld();

    $this->actingAs(tenantPerson('root@example.com', superAdmin: true))
        ->postJson('/api/v1/accounts', ['name' => 'Snazzy Resources', 'timezone' => 'Australia/Perth'])
        ->assertStatus(201)
        ->assertJsonPath('data.slug', 'snazzy-resources');

    $account = Account::where('slug', 'snazzy-resources')->firstOrFail();
    $modules = $account->modules()->get()->mapWithKeys(fn ($m) => [$m->key => (bool) $m->pivot->is_enabled]);

    expect($modules->all())->toBe(['system' => true, 'roster' => false])
        ->and(RbacAudit::query()->where('event', 'account.created')->exists())->toBeTrue();
});

it('lets a super administrator administer an account it just created', function () {
    tenantWorld();
    $root = tenantPerson('root@example.com', superAdmin: true);

    $id = $this->actingAs($root)->postJson('/api/v1/accounts', ['name' => 'Fresh'])->json('data.id');

    // Proves the core module rows exist: without them the permission check
    // inside the new account would deny even a super administrator.
    $this->actingAs($root)->putJson("/api/v1/accounts/{$id}", ['name' => 'Fresh Pty Ltd'])
        ->assertOk()->assertJsonPath('data.name', 'Fresh Pty Ltd');
    $this->actingAs($root)->postJson("/api/v1/accounts/{$id}/locations", ['name' => 'Main Camp'])
        ->assertStatus(201);
});

it('rejects a duplicate account slug and a bad timezone', function () {
    tenantWorld();

    $this->actingAs(tenantPerson('root@example.com', superAdmin: true))
        ->postJson('/api/v1/accounts', ['name' => 'Acme', 'timezone' => 'Mars/Olympus'])
        ->assertStatus(422)
        ->assertJsonValidationErrors(['slug', 'timezone']);
});

it('refuses account changes to anyone but a super administrator', function () {
    ['acme' => $acme, 'admin' => $admin] = tenantWorld();
    $user = tenantPerson('member@example.com');
    grantIn($user, $admin, $acme);

    $this->actingAs($user)->postJson('/api/v1/accounts', ['name' => 'Mine'])->assertStatus(403);
    $this->actingAs($user)->putJson("/api/v1/accounts/{$acme->id}", ['name' => 'Renamed'])->assertStatus(403);
    $this->actingAs($user)->deleteJson("/api/v1/accounts/{$acme->id}")->assertStatus(403);

    expect(Account::where('name', 'Mine')->exists())->toBeFalse()
        ->and($acme->fresh()->name)->toBe('Acme');
});

it('deletes an account only once it has no locations and no grants', function () {
    ['acme' => $acme, 'village' => $village, 'admin' => $admin] = tenantWorld();
    $root = tenantPerson('root@example.com', superAdmin: true);
    $grant = grantIn(tenantPerson('member@example.com'), $admin, $acme);

    $this->actingAs($root)->deleteJson("/api/v1/accounts/{$acme->id}")->assertStatus(422);

    $village->delete();
    $this->actingAs($root)->deleteJson("/api/v1/accounts/{$acme->id}")->assertStatus(422);

    $grant->update(['revoked_at' => now()]);
    $this->actingAs($root)->deleteJson("/api/v1/accounts/{$acme->id}")->assertSuccessful();

    expect(Account::find($acme->id))->toBeNull()
        ->and(Account::withTrashed()->find($acme->id))->not->toBeNull()
        ->and(RbacAudit::query()->where('event', 'account.deleted')->exists())->toBeTrue();
});

// ---- Locations -------------------------------------------------------------

it('lets a super administrator create, rename and delete a location', function () {
    ['acme' => $acme] = tenantWorld();
    $root = tenantPerson('root@example.com', superAdmin: true);

    $id = $this->actingAs($root)
        ->postJson("/api/v1/accounts/{$acme->id}/locations", ['name' => 'North Pit', 'state' => 'WA'])
        ->assertStatus(201)
        ->assertJsonPath('data.slug', 'north-pit')
        ->assertJsonPath('data.account_id', $acme->id)
        ->json('data.id');

    $this->actingAs($root)->putJson("/api/v1/accounts/{$acme->id}/locations/{$id}", ['name' => 'South Pit'])
        ->assertOk()->assertJsonPath('data.name', 'South Pit');

    $this->actingAs($root)->deleteJson("/api/v1/accounts/{$acme->id}/locations/{$id}")->assertSuccessful();

    expect(Location::acrossTenants()->find($id))->toBeNull()
        ->and(RbacAudit::query()->whereIn('event', ['location.created', 'location.updated', 'location.deleted'])->count())->toBe(3);
});

it('keeps location slugs unique per account, not globally', function () {
    ['acme' => $acme, 'rio' => $rio] = tenantWorld();
    $root = tenantPerson('root@example.com', superAdmin: true);

    $this->actingAs($root)->postJson("/api/v1/accounts/{$acme->id}/locations", ['name' => 'Village'])
        ->assertStatus(422)->assertJsonValidationErrors('slug');
    $this->actingAs($root)->postJson("/api/v1/accounts/{$rio->id}/locations", ['name' => 'Village'])
        ->assertStatus(201);
});

it('answers 404 for a location addressed through the wrong account', function () {
    ['acme' => $acme, 'camp' => $camp] = tenantWorld();
    $root = tenantPerson('root@example.com', superAdmin: true);

    $this->actingAs($root)->putJson("/api/v1/accounts/{$acme->id}/locations/{$camp->id}", ['name' => 'Hijacked'])
        ->assertStatus(404);
    $this->actingAs($root)->deleteJson("/api/v1/accounts/{$acme->id}/locations/{$camp->id}")
        ->assertStatus(404);

    expect($camp->fresh()->name)->toBe('Camp');
});

it('refuses location changes to anyone but a super administrator', function () {
    ['acme' => $acme, 'village' => $village, 'admin' => $admin] = tenantWorld();
    $user = tenantPerson('member@example.com');
    grantIn($user, $admin, $acme);

    $this->actingAs($user)->postJson("/api/v1/accounts/{$acme->id}/locations", ['name' => 'Mine'])->assertStatus(403);
    $this->actingAs($user)->putJson("/api/v1/accounts/{$acme->id}/locations/{$village->id}", ['name' => 'X'])->assertStatus(403);
    $this->actingAs($user)->deleteJson("/api/v1/accounts/{$acme->id}/locations/{$village->id}")->assertStatus(403);

    expect($village->fresh()->name)->toBe('Village');
});

it('deletes a location only once nobody holds a grant there', function () {
    ['acme' => $acme, 'village' => $village, 'local' => $local] = tenantWorld();
    $root = tenantPerson('root@example.com', superAdmin: true);
    $grant = grantIn(tenantPerson('worker@example.com'), $local, $acme, $village);

    $this->actingAs($root)->deleteJson("/api/v1/accounts/{$acme->id}/locations/{$village->id}")->assertStatus(422);

    $grant->update(['revoked_at' => now()]);
    $this->actingAs($root)->deleteJson("/api/v1/accounts/{$acme->id}/locations/{$village->id}")->assertSuccessful();
});

it('counts a grant that has not started yet as blocking a delete', function () {
    ['acme' => $acme, 'village' => $village, 'local' => $local] = tenantWorld();
    $grant = grantIn(tenantPerson('future@example.com'), $local, $acme, $village);
    $grant->update(['valid_from' => now()->addWeek()]);

    $this->actingAs(tenantPerson('root@example.com', superAdmin: true))
        ->deleteJson("/api/v1/accounts/{$acme->id}/locations/{$village->id}")
        ->assertStatus(422);
});
