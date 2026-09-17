<?php

namespace App\Domain\Rbac\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Permission extends Model
{
    use SoftDeletes;

    protected $fillable = ['name', 'module_id', 'description', 'is_high_risk'];

    protected function casts(): array
    {
        return ['is_high_risk' => 'boolean'];
    }

    public function module()
    {
        return $this->belongsTo(Module::class);
    }

    public function roles()
    {
        return $this->belongsToMany(Role::class);
    }
}
