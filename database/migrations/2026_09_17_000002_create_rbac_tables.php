<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * The RBAC module, built on spatie/laravel-permission.
 *
 *   modules        -- dynamic; a module is a row, not a hardcoded string
 *   account_module -- per-tenant enablement
 *   permissions    -- Spatie's table, plus module_id and risk metadata
 *   roles          -- Spatie's table; account_id doubles as Spatie's TEAM key,
 *                     so a null account_id is both "system role" here and
 *                     "global role" to Spatie. The two ideas coincide exactly.
 *   permission_role        -- Spatie's role_has_permissions, under our name
 *   model_has_permissions  -- Spatie's direct-to-model grants; unused, see below
 *   user_role_assignments  -- Spatie's model_has_roles, under our name, plus the
 *                             location dimension and the grant audit trail
 *
 * Table and column names are read from config/permission.php so the schema and
 * the package can never drift apart.
 *
 * TWO SCOPE DIMENSIONS ON A PACKAGE THAT OFFERS ONE
 * -------------------------------------------------
 * Spatie's teams feature gives one scope dimension, and account_id takes it.
 * Location is the second. It rides as a nullable column on the assignment
 * pivot -- NULL meaning "every location in this account" -- which Spatie
 * ignores on read and PermissionResolver filters on.
 *
 * That works because the third level, global, is NOT in this schema at all.
 * It is users.is_admin, a flag on a handful of people, honoured in Gate::before.
 * Spatie pins every assignment to exactly one team (see HasRoles::roles(),
 * which uses wherePivot on the team key with no OR NULL), so a scope-free
 * assignment is not expressible. The flag is not a shortcut around that; it is
 * the only way to say "everywhere" once teams own the account dimension.
 */
return new class extends Migration
{
    public function up(): void
    {
        $tables = config('permission.table_names');
        $columns = config('permission.column_names');
        $teamKey = $columns['team_foreign_key'];   // account_id
        $morphKey = $columns['model_morph_key'];   // model_id

        throw_if(empty($tables), 'config/permission.php not loaded. Run [php artisan config:clear].');

        Schema::create('modules', function (Blueprint $table) {
            $table->id();
            $table->string('key', 50)->unique()->comment('roster, travel, emergency...');
            $table->string('name', 100);
            $table->string('description')->nullable();
            $table->string('icon', 50)->nullable();
            $table->unsignedSmallInteger('sort_order')->default(100);
            $table->boolean('is_core')->default(false)
                ->comment('core modules cannot be disabled for an account');
            $table->boolean('is_active')->default(true)
                ->comment('globally available; off hides it from every account');
            $table->softDeletes();
            $table->timestamps();
            $table->index(['is_active', 'sort_order']);
        });

        Schema::create('account_module', function (Blueprint $table) {
            $table->id();
            $table->foreignId('account_id')->constrained()->cascadeOnDelete();
            $table->foreignId('module_id')->constrained()->cascadeOnDelete();
            $table->boolean('is_enabled')->default(true);
            $table->timestamp('enabled_at')->nullable();
            $table->timestamp('disabled_at')->nullable();
            $table->timestamps();
            $table->unique(['account_id', 'module_id']);
            $table->index(['account_id', 'is_enabled']);
        });

        // Spatie's permissions table. guard_name and the (name, guard_name)
        // unique key are the package's; module_id and is_high_risk are ours.
        Schema::create($tables['permissions'], function (Blueprint $table) {
            $table->id();
            $table->string('name')->comment('roster.publish');
            $table->string('guard_name', 50);
            $table->foreignId('module_id')->constrained()->restrictOnDelete();
            $table->string('description')->nullable();
            $table->boolean('is_high_risk')->default(false)
                ->comment('requires reason capture and confirmation');
            $table->softDeletes();
            $table->timestamps();
            $table->unique(['name', 'guard_name']);
            $table->index('module_id');
        });

        // Spatie's roles table. account_id is Spatie's team key: null = a system
        // role every account may use, which is exactly what null meant before.
        Schema::create($tables['roles'], function (Blueprint $table) use ($teamKey) {
            $table->id();
            $table->foreignId($teamKey)->nullable()->constrained('accounts')->cascadeOnDelete()
                ->comment('Spatie team key; null = system role, usable by every account');
            $table->string('key', 100);
            $table->string('name');
            $table->string('guard_name', 50);
            $table->string('description')->nullable();
            // 'global' is deliberately absent -- see the class docblock.
            $table->enum('scope_level', ['account', 'location'])->default('location');
            $table->boolean('is_system')->default(false);
            $table->softDeletes();
            $table->timestamps();
            $table->unique([$teamKey, 'key']);
            $table->unique([$teamKey, 'name', 'guard_name']);
            $table->index('scope_level');
        });

        // Spatie's role_has_permissions.
        Schema::create($tables['role_has_permissions'], function (Blueprint $table) use ($tables) {
            $table->foreignId('permission_id')->constrained($tables['permissions'])->cascadeOnDelete();
            $table->foreignId('role_id')->constrained($tables['roles'])->cascadeOnDelete();
            $table->primary(['permission_id', 'role_id']);
            $table->index('role_id');
        });

        // Spatie's model_has_permissions. Nothing writes to it: a permission is
        // only ever reachable through a role, so that roles stay the single
        // reviewable unit of access. The table exists because the package's
        // cache warms from it, and its absence is a hard error.
        Schema::create($tables['model_has_permissions'], function (Blueprint $table) use ($tables, $teamKey, $morphKey) {
            $table->foreignId('permission_id')->constrained($tables['permissions'])->cascadeOnDelete();
            $table->string('model_type');
            $table->unsignedBigInteger($morphKey);
            $table->unsignedBigInteger($teamKey);
            $table->index([$morphKey, 'model_type'], 'model_has_permissions_model_id_model_type_index');
            $table->primary([$teamKey, 'permission_id', $morphKey, 'model_type'],
                'model_has_permissions_permission_model_type_primary');
        });

        // Spatie's model_has_roles, under this app's name.
        //
        // Spatie's own migration makes (team, role, model, model_type) the
        // primary key. That is dropped here for a surrogate id, because it
        // cannot express either of the things this table has to hold: the same
        // role at two locations in one account, and a revoked grant kept
        // alongside its replacement. A unique index below restores the
        // duplicate protection the primary key was providing.
        Schema::create($tables['model_has_roles'], function (Blueprint $table) use ($tables, $teamKey, $morphKey) {
            $table->id();
            $table->foreignId('role_id')->constrained($tables['roles'])->cascadeOnDelete();
            $table->string('model_type');
            $table->unsignedBigInteger($morphKey);
            $table->enum('scope_level', ['account', 'location'])
                ->comment('copied from the role at grant time');
            // RESTRICT, not CASCADE: MySQL forbids a cascading FK on a column a
            // STORED generated column depends on, and these feed the scope columns.
            $table->foreignId($teamKey)->constrained('accounts')->restrictOnDelete();
            $table->foreignId('location_id')->nullable()->constrained()->restrictOnDelete()
                ->comment('null = every location in the account');
            $table->foreignId('granted_by')->nullable()->constrained('users')->nullOnDelete();
            $table->string('grant_reason')->nullable();
            $table->timestamp('valid_from')->nullable();
            $table->timestamp('valid_until')->nullable()->comment('temporary elevation');
            $table->timestamp('revoked_at')->nullable();
            $table->foreignId('revoked_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();
            $table->index([$morphKey, 'model_type'], 'model_has_roles_model_id_model_type_index');
            $table->index([$morphKey, 'revoked_at', 'valid_until'], 'ura_lookup_index');
            $table->index($teamKey, 'model_has_roles_team_foreign_key_index');
        });

        // MySQL treats NULLs as distinct in a unique index, so a plain
        // unique(model_id, role_id, account_id, location_id) would NOT stop a
        // duplicate account-wide grant. Coalesce to 0 in stored generated
        // columns, and drop revoked rows out of the index so a role can be
        // re-granted later.
        if (DB::getDriverName() === 'mysql') {
            $ura = $tables['model_has_roles'];

            DB::statement("
                ALTER TABLE `{$ura}`
                  ADD COLUMN location_scope BIGINT UNSIGNED
                      GENERATED ALWAYS AS (COALESCE(location_id, 0)) STORED,
                  ADD COLUMN active_guard TINYINT UNSIGNED
                      GENERATED ALWAYS AS (CASE WHEN revoked_at IS NULL THEN 1 ELSE NULL END) STORED
            ");

            DB::statement("
                ALTER TABLE `{$ura}`
                  ADD UNIQUE KEY ura_unique_active_grant
                      ({$morphKey}, model_type(160), role_id, {$teamKey}, location_scope, active_guard)
            ");

            // A location role must carry a location; an account role must not.
            DB::statement("
                ALTER TABLE `{$ura}`
                  ADD CONSTRAINT chk_ura_scope CHECK (
                        (scope_level = 'account'  AND location_id IS NULL)
                     OR (scope_level = 'location' AND location_id IS NOT NULL)
                  )
            ");
        }

        app('cache')
            ->store(config('permission.cache.store') != 'default' ? config('permission.cache.store') : null)
            ->forget(config('permission.cache.key'));
    }

    public function down(): void
    {
        $tables = config('permission.table_names');

        Schema::dropIfExists($tables['model_has_roles']);
        Schema::dropIfExists($tables['model_has_permissions']);
        Schema::dropIfExists($tables['role_has_permissions']);
        Schema::dropIfExists($tables['roles']);
        Schema::dropIfExists($tables['permissions']);
        Schema::dropIfExists('account_module');
        Schema::dropIfExists('modules');
    }
};
