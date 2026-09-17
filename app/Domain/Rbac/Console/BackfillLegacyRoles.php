<?php

namespace App\Domain\Rbac\Console;

use App\Domain\Rbac\Models\Role;
use App\Domain\Rbac\Models\UserRoleAssignment;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

/**
 * Migrates the legacy string role codes onto user_role_assignments.
 *
 * The mapping itself lives in config/rbac.php and is NOT yet confirmed, so
 * --commit refuses to run until every code has been given a role. --dry-run
 * works regardless and is the tool for answering "what would this do?" while
 * the mapping is still being agreed.
 */
class BackfillLegacyRoles extends Command
{
    protected $signature = 'rbac:backfill
                            {--dry-run : Report what would change and write nothing}
                            {--commit : Actually create the assignments}';

    protected $description = 'Backfill user_role_assignments from the legacy account_user / location_user role codes';

    public function handle(): int
    {
        if (! $this->option('dry-run') && ! $this->option('commit')) {
            $this->components->error('Pass --dry-run to preview, or --commit to apply.');

            return self::FAILURE;
        }

        $map = config('rbac.legacy_map');
        $unmapped = $this->unmappedCodes($map);

        $this->components->info('Legacy role codes found in the database');
        $this->distribution($map);

        if ($unmapped !== []) {
            $this->newLine();
            $this->components->warn('Unconfirmed mappings: '.implode(', ', $unmapped));
            $this->line('  These are set to null in <options=bold>config/rbac.php</>. Nothing can be');
            $this->line('  committed until each one names a role key, because a wrong mapping');
            $this->line('  silently grants or removes access.');

            if ($this->option('commit')) {
                $this->newLine();
                $this->components->error('Refusing to commit with unconfirmed mappings.');

                return self::FAILURE;
            }
        }

        // A code's role must be scoped to match the pivot it comes from:
        // account_user rows carry an account and no location, location_user
        // rows carry both. A mismatch would be rejected by chk_ura_scope at
        // insert time; catching it here gives a readable reason instead.
        $mismatched = $this->scopeMismatches($map);

        if ($mismatched !== []) {
            $this->newLine();
            $this->components->warn('Scope mismatches in config/rbac.php:');
            foreach ($mismatched as $line) {
                $this->line("  {$line}");
            }
            $this->line('  An account_user code must map to an <options=bold>account</>-scoped role,');
            $this->line('  and a location_user code to a <options=bold>location</>-scoped role.');

            if ($this->option('commit')) {
                $this->newLine();
                $this->components->error('Refusing to commit with scope mismatches.');

                return self::FAILURE;
            }
        }

        $plan = $this->buildPlan($map);
        $this->newLine();
        $this->components->info($this->option('commit') ? 'Applying' : 'Dry run — nothing will be written');
        $this->renderPlan($plan);

        if (! $this->option('commit')) {
            return self::SUCCESS;
        }

        $created = $this->apply($plan);
        $this->newLine();
        $this->components->info("Created {$created} assignments.");

        return self::SUCCESS;
    }

    /** Codes present in the data that config does not map. */
    private function unmappedCodes(array $map): array
    {
        $missing = [];

        foreach (['account' => 'account_user', 'location' => 'location_user'] as $scope => $table) {
            if (! DB::getSchemaBuilder()->hasTable($table)) {
                continue;
            }

            foreach (DB::table($table)->distinct()->whereNotNull('role')->pluck('role') as $code) {
                if (empty($map[$scope][$code])) {
                    $missing[] = "{$scope}:{$code}";
                }
            }
        }

        return $missing;
    }

    /** Mapped roles whose scope_level cannot be used by that pivot. */
    private function scopeMismatches(array $map): array
    {
        $roles = Role::whereNull('account_id')->get()->keyBy('key');
        $expected = ['account' => 'account', 'location' => 'location'];
        $problems = [];

        foreach ($expected as $scope => $required) {
            foreach ($map[$scope] ?? [] as $code => $key) {
                if (! $key) {
                    continue;
                }

                if (! isset($roles[$key])) {
                    $problems[] = "{$scope}:{$code} → '{$key}' is not an existing system role";
                    continue;
                }

                $actual = $roles[$key]->scope_level;

                if ($actual !== $required) {
                    $problems[] = "{$scope}:{$code} → '{$key}' is {$actual}-scoped, needs {$required}-scoped";
                }
            }
        }

        return $problems;
    }

    private function distribution(array $map): void
    {
        $rows = [];

        foreach (['account' => 'account_user', 'location' => 'location_user'] as $scope => $table) {
            if (! DB::getSchemaBuilder()->hasTable($table)) {
                $rows[] = [$scope, '(table absent)', '-', '-'];
                continue;
            }

            $counts = DB::table($table)->selectRaw('role, COUNT(*) as c')
                ->whereNotNull('role')->groupBy('role')->orderBy('role')->get();

            foreach ($counts as $row) {
                $target = $map[$scope][$row->role] ?? null;
                $rows[] = [$scope, $row->role, $row->c, $target ?: '— not mapped —'];
            }
        }

        $this->table(['Pivot', 'Code', 'Rows', 'Maps to role'], $rows);
    }

    /** @return array<int, array{user_id:int, role:Role, account_id:int, location_id:int|null}> */
    private function buildPlan(array $map): array
    {
        $plan = [];
        $roles = Role::whereNull('account_id')->get()->keyBy('key');

        if (DB::getSchemaBuilder()->hasTable('account_user')) {
            foreach (DB::table('account_user')->whereNull('deleted_at')->whereNotNull('role')->get() as $row) {
                $key = $map['account'][$row->role] ?? null;
                if (! $key || ! isset($roles[$key])) {
                    continue;
                }
                $plan[] = ['user_id' => (int) $row->user_id, 'role' => $roles[$key],
                           'account_id' => (int) $row->account_id, 'location_id' => null];
            }
        }

        if (DB::getSchemaBuilder()->hasTable('location_user')) {
            foreach (DB::table('location_user')->whereNull('deleted_at')->whereNotNull('role')->get() as $row) {
                $key = $map['location'][$row->role] ?? null;
                if (! $key || ! isset($roles[$key])) {
                    continue;
                }
                $plan[] = ['user_id' => (int) $row->user_id, 'role' => $roles[$key],
                           'account_id' => (int) $row->account_id, 'location_id' => (int) $row->location_id];
            }
        }

        return $plan;
    }

    private function renderPlan(array $plan): void
    {
        if ($plan === []) {
            $this->line('  Nothing to migrate with the current mapping.');

            return;
        }

        $byRole = collect($plan)->groupBy(fn ($p) => $p['role']->name)
            ->map->count()->sortDesc();

        $this->table(
            ['Role', 'Assignments to create'],
            $byRole->map(fn ($count, $role) => [$role, $count])->values()->all()
        );
    }

    private function apply(array $plan): int
    {
        $created = 0;

        DB::transaction(function () use ($plan, &$created) {
            foreach ($plan as $item) {
                /** @var Role $role */
                $role = $item['role'];

                // Idempotent: re-running must not duplicate. The unique index
                // would reject it anyway; checking first keeps the run clean.
                $exists = UserRoleAssignment::query()
                    ->where('user_id', $item['user_id'])
                    ->where('role_id', $role->id)
                    ->whereNull('revoked_at')
                    ->when($item['account_id'], fn ($q, $v) => $q->where('account_id', $v))
                    ->when($item['location_id'] === null,
                        fn ($q) => $q->whereNull('location_id'),
                        fn ($q) => $q->where('location_id', $item['location_id']))
                    ->exists();

                if ($exists) {
                    continue;
                }

                UserRoleAssignment::create([
                    'user_id'      => $item['user_id'],
                    'role_id'      => $role->id,
                    'scope_level'  => $role->scope_level,
                    'account_id'   => $item['account_id'],
                    'location_id'  => $item['location_id'],
                    'grant_reason' => config('rbac.backfill_reason'),
                    'valid_from'   => now(),
                ]);

                $created++;
            }
        });

        return $created;
    }
}
