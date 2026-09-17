<?php

use App\Domain\Identity\Models\{Account, Location, User};
use App\Domain\Rbac\Models\{Module, Permission, Role};
use Illuminate\Support\Str;

/** The class attribute of the permission chip rendering $name. */
function chipClasses(string $html, string $name): string
{
    preg_match('/<span class="([^"]*)"[^>]*>'.preg_quote($name, '/').'<\/span>/s', $html, $m);

    return $m[1] ?? '';
}

/**
 * The roles panel lists role DEFINITIONS, which are account-independent.
 * Without account context it showed travel.* as live even for an account
 * with Travel disabled — contradicting the resolver on the same screen.
 */
it('marks permissions whose module is disabled for the selected account', function () {
    $roster = Module::create(['key' => 'roster', 'name' => 'Roster']);
    $travel = Module::create(['key' => 'travel', 'name' => 'Travel']);

    $rosterView = Permission::create(['name' => 'roster.view', 'module_id' => $roster->id]);
    $travelBook = Permission::create(['name' => 'travel.book', 'module_id' => $travel->id]);

    $account = Account::create(['name' => 'City of Rio', 'slug' => 'city-of-rio']);
    Location::create(['account_id' => $account->id, 'name' => 'Community', 'slug' => 'community']);

    // Roster on, Travel off — the client did not buy Travel.
    $account->modules()->attach($roster->id, ['is_enabled' => true]);
    $account->modules()->attach($travel->id, ['is_enabled' => false]);

    $role = Role::create([
        'key' => 'travel_coordinator', 'name' => 'Travel Coordinator',
        'scope_level' => 'account', 'is_system' => true,
    ]);
    $role->permissions()->attach([$rosterView->id, $travelBook->id]);

    User::create([
        'first_name' => 'Demo', 'last_name' => 'User', 'uuid' => (string) Str::uuid(),
        'email' => 'demo@example.com', 'mobile' => '+61400000000',
    ]);

    $html = $this->get("/?account={$account->id}")->assertOk()->getContent();

    // Scope the assertions to the roles panel — these permission names also
    // appear in the permission-checker <select> further up the page.
    $rolesPanel = Str::of($html)->after('Scope decides where a role')->toString();

    expect($rolesPanel)->toContain('1 inactive in City of Rio');

    // travel.book sits in a chip whose classes include line-through.
    expect(chipClasses($rolesPanel, 'travel.book'))->toContain('line-through');

    // roster.view does not.
    expect(chipClasses($rolesPanel, 'roster.view'))->not->toContain('line-through');
});

it('marks nothing when every module is enabled for the account', function () {
    $travel = Module::create(['key' => 'travel', 'name' => 'Travel']);
    $perm = Permission::create(['name' => 'travel.book', 'module_id' => $travel->id]);

    $account = Account::create(['name' => 'Snazzy Resources', 'slug' => 'snazzy']);
    $account->modules()->attach($travel->id, ['is_enabled' => true]);

    $role = Role::create([
        'key' => 'travel_coordinator', 'name' => 'Travel Coordinator',
        'scope_level' => 'account', 'is_system' => true,
    ]);
    $role->permissions()->attach($perm->id);

    User::create([
        'first_name' => 'Demo', 'last_name' => 'User', 'uuid' => (string) Str::uuid(),
        'email' => 'demo@example.com', 'mobile' => '+61400000001',
    ]);

    $html = $this->get("/?account={$account->id}")->assertOk()->getContent();

    expect($html)->not->toContain('inactive in Snazzy Resources');
});
