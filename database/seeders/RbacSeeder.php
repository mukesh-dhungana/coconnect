<?php

namespace Database\Seeders;

use App\Domain\Identity\Models\Account;
use App\Domain\Identity\Models\Location;
use App\Domain\Rbac\Models\Module;
use App\Domain\Rbac\Models\Permission;
use App\Domain\Rbac\Models\Role;
use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Models\UserRoleAssignment;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * Seeds the demo with the shape of the real Co Connect App data:
 * the same 7 modules, 26 permissions, 11 roles and role->permission grants
 * taken from the client dump, plus accounts, locations and users to show
 * scoping and multi-role behaviour.
 */
class RbacSeeder extends Seeder
{
    public function run(): void
    {
        $modules = $this->modules();
        $permissions = $this->permissions($modules);
        $roles = $this->roles($permissions);
        [$accounts, $locations] = $this->tenants($modules);
        $this->users($roles, $accounts, $locations);
    }

    private function modules(): array
    {
        $rows = [
            ['key' => 'roster',        'name' => 'Roster',        'icon' => 'calendar',  'sort_order' => 10],
            ['key' => 'travel',        'name' => 'Travel',        'icon' => 'plane',     'sort_order' => 20],
            ['key' => 'accommodation', 'name' => 'Accommodation', 'icon' => 'bed',       'sort_order' => 30],
            ['key' => 'housekeeping',  'name' => 'Housekeeping',  'icon' => 'sparkles',  'sort_order' => 40],
            ['key' => 'emergency',     'name' => 'Emergency',     'icon' => 'siren',     'sort_order' => 50],
            ['key' => 'compliance',    'name' => 'Compliance',    'icon' => 'shield',    'sort_order' => 60],
            ['key' => 'system',        'name' => 'System',        'icon' => 'cog',       'sort_order' => 90,
             'is_core' => true, 'description' => 'Always on; cannot be disabled for an account'],
        ];

        $out = [];
        foreach ($rows as $row) {
            $out[$row['key']] = Module::create($row);
        }

        return $out;
    }

    private function permissions(array $modules): array
    {
        // name => [module key, description, high risk]
        $rows = [
            'roster.view'    => ['roster', 'View published rosters and patterns', false],
            'roster.edit'    => ['roster', 'Create or edit draft rosters and patterns', false],
            'roster.publish' => ['roster', 'Publish a draft roster to live operations', false],
            'roster.override_fatigue' => ['roster', 'Override a fatigue or rest rule block with a mandatory reason', true],

            'travel.view'     => ['travel', 'View flight schedules, manifests, and waitlists', false],
            'travel.book'     => ['travel', 'Create or amend a passenger travel booking', false],
            'travel.override_capacity' => ['travel', 'Force a booking that exceeds flight capacity', true],
            'travel.bulk_disrupt' => ['travel', 'Execute bulk cancellations or reassignments during weather events', false],

            'accommodation.view'     => ['accommodation', 'View room inventory, maps, and current allocations', false],
            'accommodation.allocate' => ['accommodation', 'Run the algorithm to allocate residents to rooms/beds', false],
            'accommodation.check_in' => ['accommodation', 'Check residents in or out of rooms and issue keys', false],
            'accommodation.override_displacement' => ['accommodation', 'Displace an already checked-in resident', true],
            'accommodation.night_audit' => ['accommodation', 'Run or approve the nightly accommodation reconciliation', false],

            'housekeeping.view'        => ['housekeeping', 'View cleaning tasks and room readiness', false],
            'housekeeping.task_update' => ['housekeeping', 'Update the status of a field cleaning task', false],
            'housekeeping.inspect'     => ['housekeeping', 'Pass or fail a formal room inspection', false],

            'emergency.view'             => ['emergency', 'View Who is On, ERT capabilities, and support directory', false],
            'emergency.handover_request' => ['emergency', 'Request a handover for a critical duty', false],
            'emergency.handover_accept'  => ['emergency', 'Accept a handover request to take accountability', false],
            'emergency.incident_activate'=> ['emergency', 'Declare and activate a new incident', true],
            'emergency.override_assignment' => ['emergency', 'Force transfer an emergency role without acceptance', true],

            'presence.view'              => ['compliance', 'View expected vs confirmed personnel manifest', false],
            'presence.manual_correction' => ['compliance', 'Manually override presence status without a swipe event', true],
            'presence.welfare_resolve'   => ['compliance', 'Assign and resolve welfare checks and AOD exceptions', false],

            'system.audit_view'         => ['system', 'View the immutable audit ledger', false],
            'system.integration_manage' => ['system', 'Configure Serko, Gallagher, and Alcolizer API connections', true],
        ];

        $out = [];
        foreach ($rows as $name => [$moduleKey, $description, $highRisk]) {
            $out[$name] = Permission::create([
                'name'         => $name,
                'module_id'    => $modules[$moduleKey]->id,
                'description'  => $description,
                'is_high_risk' => $highRisk,
            ]);
        }

        return $out;
    }

    private function roles(array $permissions): array
    {
        // name => [scope, key, [permission names]]
        $rows = [
            'System Administrator' => ['global', 'system_administrator', array_keys($permissions)],
            'Roster Coordinator' => ['account', 'roster_coordinator', [
                'roster.view', 'roster.edit', 'roster.publish', 'roster.override_fatigue',
                'travel.view', 'accommodation.view', 'emergency.view', 'presence.view',
            ]],
            'Travel Coordinator' => ['account', 'travel_coordinator', [
                'travel.view', 'travel.book', 'travel.override_capacity', 'travel.bulk_disrupt',
                'roster.view', 'accommodation.view',
            ]],
            'Village Accommodation Manager' => ['location', 'village_accommodation_manager', [
                'accommodation.view', 'accommodation.allocate', 'accommodation.check_in',
                'accommodation.override_displacement', 'accommodation.night_audit',
                'housekeeping.view', 'housekeeping.inspect', 'roster.view', 'presence.view',
            ]],
            'Housekeeping Supervisor' => ['location', 'housekeeping_supervisor', [
                'housekeeping.view', 'housekeeping.task_update', 'housekeeping.inspect',
                'accommodation.view',
            ]],
            'Housekeeper' => ['location', 'housekeeper', [
                'housekeeping.view', 'housekeeping.task_update',
            ]],
            'HSE & Compliance Manager' => ['account', 'hse_and_compliance_manager', [
                'emergency.view', 'emergency.handover_request', 'emergency.handover_accept',
                'emergency.incident_activate', 'emergency.override_assignment',
                'presence.view', 'presence.manual_correction', 'presence.welfare_resolve',
                'roster.view', 'system.audit_view',
            ]],
            'EMT Leader / Incident Controller' => ['location', 'emt_leader_incident_controller', [
                'emergency.view', 'emergency.handover_request', 'emergency.handover_accept',
                'emergency.incident_activate', 'emergency.override_assignment',
                'presence.view', 'presence.manual_correction', 'system.audit_view',
            ]],
            'ERT Member' => ['location', 'ert_member', [
                'emergency.view', 'emergency.handover_request', 'emergency.handover_accept',
                'presence.view',
            ]],
            'Site Worker / Contractor' => ['location', 'site_worker_contractor', [
                'roster.view', 'travel.view', 'accommodation.view',
            ]],
            'Auditor / Assurance Reviewer' => ['account', 'auditor_assurance_reviewer', [
                'roster.view', 'travel.view', 'accommodation.view', 'housekeeping.view',
                'emergency.view', 'presence.view', 'system.audit_view',
            ]],
        ];

        $out = [];
        foreach ($rows as $name => [$scope, $key, $perms]) {
            $role = Role::create([
                'account_id'  => null,          // system role
                'key'         => $key,
                'name'        => $name,
                'scope_level' => $scope,
                'is_system'   => true,
            ]);
            $role->permissions()->sync(collect($perms)->map(fn ($p) => $permissions[$p]->id)->all());
            $out[$name] = $role;
        }

        return $out;
    }

    private function tenants(array $modules): array
    {
        $accounts = [];
        $locations = [];

        $spec = [
            'Snazzy Resources' => ['snazzy-resources', ['Village', 'Site'],
                ['roster', 'travel', 'accommodation', 'housekeeping', 'emergency', 'compliance', 'system']],
            // Deliberately has NO travel module: shows the commercial boundary.
            'City of Rio'      => ['city-of-rio', ['Community', 'LGA'],
                ['roster', 'accommodation', 'emergency', 'compliance', 'system']],
        ];

        foreach ($spec as $name => [$slug, $locationNames, $enabled]) {
            $account = Account::create([
                'name' => $name, 'slug' => $slug,
                'timezone' => 'Australia/Perth', 'locale' => 'en-AU',
            ]);

            foreach ($modules as $key => $module) {
                $account->modules()->attach($module->id, [
                    'is_enabled' => in_array($key, $enabled, true),
                    'enabled_at' => in_array($key, $enabled, true) ? now() : null,
                    'created_at' => now(), 'updated_at' => now(),
                ]);
            }

            foreach ($locationNames as $locationName) {
                $locations[] = Location::create([
                    'account_id' => $account->id,
                    'name'       => $locationName,
                    'slug'       => Str::slug($name.'-'.$locationName),
                ]);
            }

            $accounts[$name] = $account;
        }

        return [$accounts, $locations];
    }

    private function users(array $roles, array $accounts, array $locations): void
    {
        $snazzy = $accounts['Snazzy Resources'];
        $rio    = $accounts['City of Rio'];
        $village = collect($locations)->firstWhere('name', 'Village');
        $site    = collect($locations)->firstWhere('name', 'Site');
        $community = collect($locations)->firstWhere('name', 'Community');

        $make = function (string $first, string $last, string $email) {
            return User::create([
                'first_name' => $first, 'last_name' => $last,
                'uuid' => (string) Str::uuid(), 'email' => $email,
                'mobile' => '+614'.random_int(10000000, 99999999),
                'password' => Hash::make('password'),
            ]);
        };

        $erin  = $make('Erin', 'Bell', 'erin@coconnectapp.com');
        $admin = $make('Admin', 'Manager', 'admin@nano.rocks');
        $trav  = $make('Manager', 'Manager', 'manager@nano.rocks');
        $brad  = $make('Brad', 'Smith', 'brad@campconnect.com.au');
        $keira = $make('Keira', 'Novak', 'keira@campconnect.com.au');
        $petr  = $make('Petr', 'Emergency', 'petr.emergency@campconnect.com.au');
        $worker= $make('Demo', 'User', 'demo@example.com');

        $grant = fn (User $u, string $role, $acc = null, $loc = null, $until = null, $by = null) =>
            UserRoleAssignment::create([
                'user_id'     => $u->id,
                'role_id'     => $roles[$role]->id,
                'scope_level' => $roles[$role]->scope_level,
                'account_id'  => $acc?->id,
                'location_id' => $loc?->id,
                'granted_by'  => $by?->id,
                'valid_from'  => now()->subDay(),
                'valid_until' => $until,
            ]);

        // Global
        $grant($erin, 'System Administrator');

        // Account-scoped
        $grant($admin, 'Roster Coordinator', $snazzy, null, null, $erin);
        $grant($trav,  'Travel Coordinator', $snazzy, null, null, $erin);

        // The same person coordinating travel for a SECOND account.
        $grant($trav,  'Travel Coordinator', $rio, null, null, $erin);

        // Location-scoped
        $grant($brad,  'Village Accommodation Manager', $snazzy, $village, null, $erin);
        $grant($keira, 'Housekeeping Supervisor', $snazzy, $village, null, $brad);

        // MULTI-ROLE: ERT Member permanently, plus a TEMPORARY EMT Leader
        // elevation that expires on its own in two hours.
        $grant($petr, 'ERT Member', $snazzy, $site, null, $erin);
        $grant($petr, 'EMT Leader / Incident Controller', $snazzy, $site, now()->addHours(2), $erin);

        // A worker at two locations in the same account.
        $grant($worker, 'Site Worker / Contractor', $snazzy, $village, null, $admin);
        $grant($worker, 'Site Worker / Contractor', $snazzy, $site, null, $admin);

        // Account membership pivots (legacy shape, kept in sync).
        foreach ([$erin, $admin, $trav, $brad, $keira, $petr, $worker] as $u) {
            $snazzy->users()->attach($u->id, ['type' => 'employee', 'source' => 'seed', 'created_at' => now(), 'updated_at' => now()]);
        }
        $rio->users()->attach($trav->id, ['type' => 'contractor', 'source' => 'seed', 'created_at' => now(), 'updated_at' => now()]);
    }
}
