<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A temporary grant stops resolving the moment valid_until passes -- no job is
 * involved in that. This column only records that the expiry has been written
 * to the audit log (rbac:record-expiries), so each one is logged exactly once.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table(config('permission.table_names.model_has_roles'), function (Blueprint $table) {
            $table->timestamp('expiry_recorded_at')->nullable()->after('valid_until')
                ->comment('when role.expired was written to the audit log');
        });
    }

    public function down(): void
    {
        Schema::table(config('permission.table_names.model_has_roles'), function (Blueprint $table) {
            $table->dropColumn('expiry_recorded_at');
        });
    }
};
