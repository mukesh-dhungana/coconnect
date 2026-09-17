<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Mirrors the tables that already exist in the Co Connect App database.
 * In the real deployment these are NOT created by this project -- the RBAC
 * module attaches to them. They are defined here so the demo runs standalone.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('accounts', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('slug')->index();
            $table->string('abn')->nullable();
            $table->string('timezone')->nullable();
            $table->string('locale')->nullable();
            $table->softDeletes();
            $table->timestamps();
        });

        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('first_name');
            $table->string('last_name');
            $table->uuid('uuid')->unique();
            $table->string('email')->nullable()->index();
            $table->string('mobile')->nullable()->unique();
            $table->string('mobile_country')->default('AU');
            $table->string('password')->nullable();
            $table->boolean('is_admin')->default(false);
            $table->string('timezone')->nullable();
            $table->string('language')->nullable();
            $table->rememberToken();
            $table->timestamp('email_verified_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            $table->softDeletes();
            $table->timestamps();
        });

        Schema::create('locations', function (Blueprint $table) {
            $table->id();
            $table->foreignId('account_id')->constrained()->cascadeOnDelete();
            $table->string('name');
            $table->string('slug')->index();
            $table->string('suburb')->nullable();
            $table->string('state')->nullable();
            $table->softDeletes();
            $table->timestamps();
        });

        // Legacy membership pivots. The string `role` columns on these are what
        // the RBAC module replaces; they are kept for the migration path.
        Schema::create('account_user', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->foreignId('account_id')->constrained()->cascadeOnDelete();
            $table->string('roster')->nullable();
            $table->string('workgroup')->nullable();
            $table->string('employer')->nullable();
            $table->string('type')->nullable()->comment('employee | contractor');
            $table->string('source')->nullable();
            $table->string('role')->nullable()->index()->comment('LEGACY string code 10-40');
            $table->timestamp('invited_at')->nullable();
            $table->timestamp('valid_until')->nullable();
            $table->softDeletes();
            $table->timestamps();
        });

        Schema::create('location_user', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->foreignId('account_id')->constrained()->cascadeOnDelete();
            $table->foreignId('location_id')->constrained()->cascadeOnDelete();
            $table->string('role')->nullable()->index()->comment('LEGACY string code 120/130');
            $table->softDeletes();
            $table->timestamps();
        });

        Schema::create('sessions', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->longText('payload');
            $table->integer('last_activity')->index();
        });

        Schema::create('cache', function (Blueprint $table) {
            $table->string('key')->primary();
            $table->mediumText('value');
            $table->integer('expiration');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('cache');
        Schema::dropIfExists('sessions');
        Schema::dropIfExists('location_user');
        Schema::dropIfExists('account_user');
        Schema::dropIfExists('locations');
        Schema::dropIfExists('users');
        Schema::dropIfExists('accounts');
    }
};
