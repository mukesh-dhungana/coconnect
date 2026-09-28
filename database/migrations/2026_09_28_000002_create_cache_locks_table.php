<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The database cache store keeps its atomic locks here. The core migration
 * created `cache` but not this, so any Cache::lock() -- including the
 * scheduler's withoutOverlapping() and onOneServer() -- failed on a missing
 * table. Laravel's own schema.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('cache_locks', function (Blueprint $table) {
            $table->string('key')->primary();
            $table->string('owner');
            $table->integer('expiration')->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('cache_locks');
    }
};
