<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * The RBAC module.
 *
 *   modules      -- dynamic; a module is a row, not a hardcoded string
 *   account_module -- per-tenant enablement
 *   permissions  -- belongs to a module
 *   roles        -- system (account_id null) or account-defined
 *   permission_role
 *   user_role_assignments -- a user may hold many roles, at different scopes
 */
return new class extends Migration
{
    public function up(): void
    {
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

        Schema::create('permissions', function (Blueprint $table) {
            $table->id();
            $table->string('name')->unique()->comment('roster.publish');
            $table->foreignId('module_id')->constrained()->restrictOnDelete();
            $table->string('description')->nullable();
            $table->boolean('is_high_risk')->default(false)
                  ->comment('requires reason capture and confirmation');
            $table->softDeletes();
            $table->timestamps();
            $table->index('module_id');
        });

        Schema::create('roles', function (Blueprint $table) {
            $table->id();
            // null = system role, available to every account
            $table->foreignId('account_id')->nullable()->constrained()->cascadeOnDelete();
            $table->string('key', 100);
            $table->string('name');
            $table->string('description')->nullable();
            $table->enum('scope_level', ['global', 'account', 'location'])->default('location');
            $table->boolean('is_system')->default(false);
            $table->softDeletes();
            $table->timestamps();
            $table->unique(['account_id', 'key']);
            $table->index('scope_level');
        });

        Schema::create('permission_role', function (Blueprint $table) {
            $table->foreignId('role_id')->constrained()->cascadeOnDelete();
            $table->foreignId('permission_id')->constrained()->cascadeOnDelete();
            $table->primary(['role_id', 'permission_id']);
            $table->index('permission_id');
        });

        Schema::create('user_role_assignments', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->foreignId('role_id')->constrained()->cascadeOnDelete();
            $table->enum('scope_level', ['global', 'account', 'location'])
                  ->comment('copied from the role at grant time');
            // RESTRICT, not CASCADE: MySQL forbids a cascading FK on a column a
            // STORED generated column depends on, and these feed the scope columns.
            $table->foreignId('account_id')->nullable()->constrained()->restrictOnDelete();
            $table->foreignId('location_id')->nullable()->constrained()->restrictOnDelete();
            $table->foreignId('granted_by')->nullable()->constrained('users')->nullOnDelete();
            $table->string('grant_reason')->nullable();
            $table->timestamp('valid_from')->nullable();
            $table->timestamp('valid_until')->nullable()->comment('temporary elevation');
            $table->timestamp('revoked_at')->nullable();
            $table->foreignId('revoked_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();
            $table->index(['user_id', 'revoked_at', 'valid_until'], 'ura_lookup_index');
        });

        // MySQL treats NULLs as distinct in a unique index, so a plain
        // unique(user_id, role_id, account_id, location_id) would NOT stop a
        // duplicate GLOBAL grant. Coalesce to 0 in stored generated columns, and
        // drop revoked rows out of the index so a role can be re-granted later.
        if (DB::getDriverName() === 'mysql') {
            DB::statement("
                ALTER TABLE user_role_assignments
                  ADD COLUMN account_scope BIGINT UNSIGNED
                      GENERATED ALWAYS AS (COALESCE(account_id, 0)) STORED,
                  ADD COLUMN location_scope BIGINT UNSIGNED
                      GENERATED ALWAYS AS (COALESCE(location_id, 0)) STORED,
                  ADD COLUMN active_guard TINYINT UNSIGNED
                      GENERATED ALWAYS AS (CASE WHEN revoked_at IS NULL THEN 1 ELSE NULL END) STORED
            ");

            DB::statement("
                ALTER TABLE user_role_assignments
                  ADD UNIQUE KEY ura_unique_active_grant
                      (user_id, role_id, account_scope, location_scope, active_guard)
            ");

            // A location role must carry a location; a global role must carry none.
            DB::statement("
                ALTER TABLE user_role_assignments
                  ADD CONSTRAINT chk_ura_scope CHECK (
                        (scope_level = 'global'   AND account_id IS NULL     AND location_id IS NULL)
                     OR (scope_level = 'account'  AND account_id IS NOT NULL AND location_id IS NULL)
                     OR (scope_level = 'location' AND account_id IS NOT NULL AND location_id IS NOT NULL)
                  )
            ");
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('user_role_assignments');
        Schema::dropIfExists('permission_role');
        Schema::dropIfExists('roles');
        Schema::dropIfExists('permissions');
        Schema::dropIfExists('account_module');
        Schema::dropIfExists('modules');
    }
};
