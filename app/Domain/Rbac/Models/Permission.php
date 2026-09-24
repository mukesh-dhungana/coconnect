<?php

namespace App\Domain\Rbac\Models;

use Illuminate\Database\Eloquent\SoftDeletes;
use Spatie\Permission\Models\Permission as SpatiePermission;

/**
 * Spatie's Permission, tied to the module that sells it.
 *
 * module_id is what makes a permission commercially revocable: an account that
 * has not enabled the module is denied the permission no matter which role
 * carries it. Spatie has no concept of that, so User::hasPermissionTo() enforces
 * it via PermissionCatalog.
 */
class Permission extends SpatiePermission
{
    use SoftDeletes;

    protected $fillable = ['name', 'guard_name', 'module_id', 'description', 'is_high_risk'];

    protected function casts(): array
    {
        return ['is_high_risk' => 'boolean'];
    }

    public function module()
    {
        return $this->belongsTo(Module::class);
    }
}
