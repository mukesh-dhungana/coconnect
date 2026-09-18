<?php

use App\Domain\Identity\Models\{Account, Location, User};
use App\Domain\Rbac\Models\{Module, Permission, Role, UserRoleAssignment};
use App\Support\Tenancy\TenantContext;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/*
| The response envelope, the exception handler and tenant isolation.
|
| These are the guarantees clients build against: a success always looks the
| same, a failure never leaks the filesystem, and one account can never read
| another's rows.
*/

function person(string $email): User
{
    return User::create([
        'first_name' => 'Test', 'last_name' => 'Person', 'uuid' => (string) Str::uuid(),
        'email' => $email, 'mobile' => '+614'.random_int(10000000, 99999999),
        'password' => Hash::make('password'),
    ]);
}

function twoAccounts(): array
{
    $system = Module::create(['key' => 'system', 'name' => 'System', 'is_core' => true]);
    $audit  = Permission::create(['name' => 'system.audit_view', 'module_id' => $system->id]);

    $acme = Account::create(['name' => 'Acme', 'slug' => 'acme']);
    $rio  = Account::create(['name' => 'Rio', 'slug' => 'rio']);

    foreach ([$acme, $rio] as $a) {
        $a->modules()->attach($system->id, ['is_enabled' => true]);
    }

    $acmeSite = Location::create(['account_id' => $acme->id, 'name' => 'Acme Village', 'slug' => 'acme-village']);
    $rioSite  = Location::create(['account_id' => $rio->id, 'name' => 'Rio Camp', 'slug' => 'rio-camp']);

    $viewer = Role::create([
        'key' => 'viewer', 'name' => 'Viewer', 'scope_level' => 'account', 'is_system' => true,
    ]);
    $viewer->permissions()->attach($audit->id);

    return compact('acme', 'rio', 'acmeSite', 'rioSite', 'viewer');
}

/** Grants an account-scoped role, the ordinary single-tenant employee. */
function memberOf(Account $account, Role $role, string $email): User
{
    $user = person($email);

    UserRoleAssignment::create([
        'user_id' => $user->id, 'role_id' => $role->id,
        'scope_level' => 'account', 'account_id' => $account->id, 'valid_from' => now(),
    ]);

    return $user;
}

// ---- Response envelope -----------------------------------------------------

it('wraps every successful response in a data key', function () {
    ['acme' => $acme, 'viewer' => $viewer] = twoAccounts();

    $this->actingAs(memberOf($acme, $viewer, 'viewer@example.com'))
        ->getJson('/api/v1/me')
        ->assertOk()
        ->assertJsonStructure(['data' => ['user' => ['id', 'name', 'email'], 'roles', 'permissions']]);
});

it('returns paginated results as data plus meta', function () {
    ['acme' => $acme, 'viewer' => $viewer] = twoAccounts();

    $this->actingAs(memberOf($acme, $viewer, 'viewer@example.com'))
        ->getJson('/api/v1/audit')
        ->assertOk()
        ->assertJsonStructure(['data', 'meta' => ['total', 'per_page', 'current_page', 'last_page']]);
});

// ---- Exception handler -----------------------------------------------------

it('answers an unknown endpoint with a message and no stack trace', function () {
    $response = $this->getJson('/api/v1/user');   // singular: does not exist

    $response->assertStatus(404)->assertExactJson(['message' => 'Endpoint not found.']);

    // The screenshot that prompted this: absolute paths in the body.
    expect($response->getContent())->not->toContain('/Users/')
        ->and($response->getContent())->not->toContain('vendor/laravel');
});

it('answers a wrong method with 405 rather than an exception page', function () {
    $this->deleteJson('/api/v1/login')
        ->assertStatus(405)
        ->assertExactJson(['message' => 'Method not allowed for this endpoint.']);
});

it('answers an unauthenticated API call with 401 even without an Accept header', function () {
    twoAccounts();

    // No Accept: application/json. Before shouldRenderJsonWhen() this produced
    // a 500 — "Route [login] not defined".
    $this->get('/api/v1/users')->assertStatus(401)
        ->assertExactJson(['message' => 'Unauthenticated.']);
});

it('returns validation failures as 422 with a field map', function () {
    ['acme' => $acme, 'viewer' => $viewer] = twoAccounts();

    $this->actingAs(memberOf($acme, $viewer, 'viewer@example.com'))
        ->postJson('/api/v1/users', ['first_name' => 'No Email'])
        ->assertStatus(403);   // viewer cannot manage; permission runs first
});

// ---- Tenant isolation ------------------------------------------------------

it('filters tenant-owned rows to the current account', function () {
    ['acme' => $acme, 'rio' => $rio] = twoAccounts();
    $tenant = app(TenantContext::class);

    $tenant->set($acme);
    expect(Location::pluck('name')->all())->toBe(['Acme Village']);

    $tenant->set($rio);
    expect(Location::pluck('name')->all())->toBe(['Rio Camp']);

    // And the escape hatch still sees everything.
    expect(Location::acrossTenants()->count())->toBe(2);
});

it('stamps account_id on create from the tenant context', function () {
    ['rio' => $rio] = twoAccounts();

    app(TenantContext::class)->set($rio);
    $created = Location::create(['name' => 'New Camp', 'slug' => 'new-camp']);

    expect($created->account_id)->toBe($rio->id);
});

it('refuses a request for an account the caller holds no grant in', function () {
    ['acme' => $acme, 'rio' => $rio, 'viewer' => $viewer] = twoAccounts();

    $this->actingAs(memberOf($acme, $viewer, 'acme-only@example.com'))
        ->getJson("/api/v1/accounts/{$rio->id}/modules")
        ->assertStatus(403)
        ->assertExactJson(['message' => 'You do not have access to this account.']);
});

it('lets a global role act inside any account', function () {
    ['acme' => $acme, 'rio' => $rio] = twoAccounts();

    $admin = Role::create([
        'key' => 'admin', 'name' => 'Administrator', 'scope_level' => 'global', 'is_system' => true,
    ]);
    $admin->permissions()->attach(Permission::where('name', 'system.audit_view')->firstOrFail()->id);

    $user = person('global@example.com');
    UserRoleAssignment::create([
        'user_id' => $user->id, 'role_id' => $admin->id, 'scope_level' => 'global', 'valid_from' => now(),
    ]);

    foreach ([$acme, $rio] as $account) {
        $this->actingAs($user)->getJson("/api/v1/accounts/{$account->id}/modules")->assertOk();
    }
});
