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
| The Site Administrator, as the client confirmed it:
|
|   super admin creates account -> location -> first user -> assigns roles;
|   the Site Administrator then adds and edits the rest of their account.
|
| A Site Administrator cannot even see people in another account: they are a
| 404, they are missing from the list, and they are missing from the audit log.
*/

function siteWorld(): array
{
    $system = Module::create(['key' => 'system', 'name' => 'System', 'is_core' => true]);

    $perm = fn (string $name) => Permission::create(['name' => $name, 'module_id' => $system->id]);
    $audit = $perm('system.audit_view');
    $users = $perm('system.user_manage');
    $perm('system.account_manage');
    $perm('system.location_manage');

    // The seeded roles, reduced to what these tests need.
    $siteAdmin = Role::create(['key' => 'site_administrator', 'name' => 'Site Administrator', 'scope_level' => 'account', 'is_system' => true]);
    $siteAdmin->permissions()->attach([$audit->id, $users->id]);

    // Operational, but holds audit_view -- as HSE & Compliance Manager does.
    $coordinator = Role::create(['key' => 'coordinator', 'name' => 'Coordinator', 'scope_level' => 'account', 'is_system' => true]);
    $coordinator->permissions()->attach($audit->id);

    $housekeeper = Role::create(['key' => 'housekeeper', 'name' => 'Housekeeper', 'scope_level' => 'location', 'is_system' => true]);

    $acme = Account::create(['name' => 'Acme', 'slug' => 'acme']);
    $rio = Account::create(['name' => 'Rio', 'slug' => 'rio']);
    foreach ([$acme, $rio] as $account) {
        $account->modules()->attach($system->id, ['is_enabled' => true]);
    }

    return compact('acme', 'rio', 'siteAdmin', 'coordinator', 'housekeeper');
}

function sitePerson(string $email, ?Account $memberOf = null, bool $superAdmin = false): User
{
    $user = User::create([
        'first_name' => Str::before($email, '@'), 'last_name' => 'Person', 'uuid' => (string) Str::uuid(),
        'email' => $email, 'password' => Hash::make('password'),
    ]);
    $user->forceFill(['is_admin' => $superAdmin])->save();
    $memberOf?->users()->attach($user->id);

    return $user;
}

function siteGrant(User $user, Role $role, Account $account, ?Location $location = null): UserRoleAssignment
{
    return UserRoleAssignment::create([
        'model_id' => $user->id, 'model_type' => $user::class, 'role_id' => $role->id,
        'scope_level' => $role->scope_level, 'account_id' => $account->id,
        'location_id' => $location?->id, 'valid_from' => now(),
    ]);
}

/** A Site Administrator of Acme, with one colleague there and one person in Rio. */
function siteAdminOfAcme(): array
{
    $world = siteWorld();
    $sam = sitePerson('sam@example.com', $world['acme']);
    siteGrant($sam, $world['siteAdmin'], $world['acme']);

    $colleague = sitePerson('colleague@example.com', $world['acme']);
    $stranger = sitePerson('stranger@example.com', $world['rio']);
    siteGrant($stranger, $world['coordinator'], $world['rio']);

    return $world + compact('sam', 'colleague', 'stranger');
}

// ---- The onboarding flow ---------------------------------------------------

it('runs the confirmed onboarding flow end to end', function () {
    ['siteAdmin' => $siteAdminRole, 'housekeeper' => $housekeeper] = siteWorld();
    $root = sitePerson('root@example.com', superAdmin: true);

    // Super admin: account -> location -> first user -> Site Administrator.
    $accountId = $this->actingAs($root)->postJson('/api/v1/accounts', ['name' => 'Snazzy'])
        ->assertStatus(201)->json('data.id');
    $locationId = $this->actingAs($root)->postJson("/api/v1/accounts/{$accountId}/locations", ['name' => 'Village'])
        ->assertStatus(201)->json('data.id');
    $firstId = $this->actingAs($root)->postJson('/api/v1/users', [
        'first_name' => 'Sam', 'last_name' => 'Admin', 'email' => 'sam@snazzy.test', 'account_id' => $accountId,
    ])->assertStatus(201)->json('data.id');
    $this->actingAs($root)->postJson("/api/v1/users/{$firstId}/assignments", [
        'role_id' => $siteAdminRole->id, 'account_id' => $accountId,
    ])->assertStatus(201);

    // Site Administrator: invites the rest of the account.
    $sam = User::findOrFail($firstId);
    $keiraId = $this->actingAs($sam)->postJson('/api/v1/users', [
        'first_name' => 'Keira', 'last_name' => 'Novak', 'email' => 'keira@snazzy.test',
    ])->assertStatus(201)->json('data.id');
    $this->actingAs($sam)->postJson("/api/v1/users/{$keiraId}/assignments", [
        'role_id' => $housekeeper->id, 'account_id' => $accountId, 'location_id' => $locationId,
    ])->assertStatus(201);
    $this->actingAs($sam)->putJson("/api/v1/users/{$keiraId}", ['last_name' => 'Novak-Hart'])
        ->assertOk()->assertJsonPath('data.name', 'Keira Novak-Hart');

    expect(User::findOrFail($keiraId)->accounts()->pluck('accounts.id')->all())->toBe([$accountId])
        ->and(RbacAudit::query()->where('event', 'user.updated')->exists())->toBeTrue();

    // ...but configuring the platform is not theirs.
    $this->actingAs($sam)->postJson('/api/v1/accounts', ['name' => 'Mine'])->assertStatus(403);
    $this->actingAs($sam)->postJson("/api/v1/accounts/{$accountId}/locations", ['name' => 'Camp'])->assertStatus(403);
});

// ---- Cannot see another account's people -----------------------------------

it("lists only the site administrator's own account", function () {
    ['sam' => $sam, 'acme' => $acme] = siteAdminOfAcme();

    $emails = collect($this->actingAs($sam)->getJson("/api/v1/users?account_id={$acme->id}")
        ->assertOk()->json('data'))->pluck('email');

    expect($emails->sort()->values()->all())->toBe(['colleague@example.com', 'sam@example.com']);
});

it('refuses listing another account outright', function () {
    ['sam' => $sam, 'rio' => $rio] = siteAdminOfAcme();

    $this->actingAs($sam)->getJson("/api/v1/users?account_id={$rio->id}")->assertStatus(403);
});

it('shows a person shared with another account with only this account\'s roles', function () {
    ['sam' => $sam, 'acme' => $acme, 'rio' => $rio, 'coordinator' => $coordinator] = siteAdminOfAcme();
    $shared = sitePerson('shared@example.com', $acme);
    siteGrant($shared, $coordinator, $acme);
    siteGrant($shared, $coordinator, $rio);

    $row = collect($this->actingAs($sam)->getJson("/api/v1/users?account_id={$acme->id}")->json('data'))
        ->firstWhere('email', 'shared@example.com');

    expect(collect($row['assignments'])->pluck('account')->all())->toBe(['Acme']);

    $this->actingAs($sam)->getJson("/api/v1/users/{$shared->id}/assignments")
        ->assertOk()->assertJsonCount(1, 'data.assignments');
});

it('treats a person in another account as not found', function () {
    ['sam' => $sam, 'stranger' => $stranger, 'coordinator' => $coordinator, 'acme' => $acme] = siteAdminOfAcme();

    $this->actingAs($sam)->getJson("/api/v1/users/{$stranger->id}/assignments")->assertStatus(404);
    $this->actingAs($sam)->getJson("/api/v1/users/{$stranger->id}/check?permission=system.audit_view")->assertStatus(404);
    $this->actingAs($sam)->putJson("/api/v1/users/{$stranger->id}", ['first_name' => 'Hijacked'])->assertStatus(404);
    $this->actingAs($sam)->postJson("/api/v1/users/{$stranger->id}/assignments", [
        'role_id' => $coordinator->id, 'account_id' => $acme->id,
    ])->assertStatus(404);

    expect($stranger->fresh()->first_name)->toBe('stranger')
        ->and($stranger->roleAssignments()->where('account_id', $acme->id)->exists())->toBeFalse();
});

it("keeps another account's events out of the audit log", function () {
    ['sam' => $sam, 'acme' => $acme, 'rio' => $rio] = siteAdminOfAcme();
    RbacAudit::record('user.created', $sam, ['account_id' => $acme->id, 'user' => 'Acme hire']);
    RbacAudit::record('user.created', $sam, ['account_id' => $rio->id, 'user' => 'Rio hire']);

    // With no filter, and with a filter naming the account.
    foreach (['/api/v1/audit', "/api/v1/audit?account_id={$acme->id}"] as $url) {
        $users = collect($this->actingAs($sam)->getJson($url)->assertOk()->json('data'))->pluck('properties.user');

        expect($users->all())->toContain('Acme hire')->not->toContain('Rio hire');
    }
});

// ---- Editing -----------------------------------------------------------------

it('refuses a site administrator editing a super administrator', function () {
    ['sam' => $sam, 'acme' => $acme] = siteAdminOfAcme();
    $root = sitePerson('root@example.com', $acme, superAdmin: true);

    $this->actingAs($sam)->putJson("/api/v1/users/{$root->id}", ['email' => 'mine@example.com'])->assertStatus(403);

    expect($root->fresh()->email)->toBe('root@example.com');
});

it('refuses a site administrator editing someone who also belongs to another account', function () {
    ['sam' => $sam, 'acme' => $acme, 'rio' => $rio, 'coordinator' => $coordinator] = siteAdminOfAcme();
    $shared = sitePerson('shared@example.com', $acme);
    siteGrant($shared, $coordinator, $rio);

    // Changing a shared login's email would take over their Rio access too.
    $this->actingAs($sam)->putJson("/api/v1/users/{$shared->id}", ['email' => 'mine@example.com'])->assertStatus(403);

    expect($shared->fresh()->email)->toBe('shared@example.com');
});

it('lets a super administrator edit anyone', function () {
    ['stranger' => $stranger] = siteAdminOfAcme();

    $this->actingAs(sitePerson('root@example.com', superAdmin: true))
        ->putJson("/api/v1/users/{$stranger->id}", ['mobile' => '+61400000000'])
        ->assertOk()->assertJsonPath('data.mobile', '+61400000000');
});

it('rejects an email another person already uses', function () {
    ['sam' => $sam, 'colleague' => $colleague] = siteAdminOfAcme();

    $this->actingAs($sam)->putJson("/api/v1/users/{$colleague->id}", ['email' => 'stranger@example.com'])
        ->assertStatus(422)->assertJsonValidationErrors('email');
});

it('refuses an operational role adding or editing people, even with audit access', function () {
    ['acme' => $acme, 'coordinator' => $coordinator, 'colleague' => $colleague] = siteAdminOfAcme();
    $hse = sitePerson('hse@example.com', $acme);
    siteGrant($hse, $coordinator, $acme);

    $this->actingAs($hse)->putJson("/api/v1/users/{$colleague->id}", ['first_name' => 'X'])->assertStatus(403);
    $this->actingAs($hse)->postJson('/api/v1/users', [
        'first_name' => 'No', 'last_name' => 'Way', 'email' => 'noway@example.com',
    ])->assertStatus(403);

    // It can still read its own account's directory.
    $this->actingAs($hse)->getJson('/api/v1/users')->assertOk()
        ->assertJsonMissing(['email' => 'stranger@example.com']);
});
