<?php

namespace App\Domain\Identity\Models;

use App\Domain\Rbac\Models\Module;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Account extends Model
{
    use SoftDeletes;

    protected $fillable = ['name', 'slug', 'abn', 'timezone', 'locale'];

    public function locations() { return $this->hasMany(Location::class); }

    public function users()
    {
        return $this->belongsToMany(User::class, 'account_user')
            ->withPivot(['roster', 'workgroup', 'employer', 'type', 'role'])
            ->withTimestamps();
    }

    public function modules()
    {
        return $this->belongsToMany(Module::class, 'account_module')
            ->withPivot(['is_enabled', 'enabled_at', 'disabled_at'])
            ->withTimestamps();
    }

    /** Module keys this account may actually use. */
    public function enabledModuleKeys(): array
    {
        return $this->modules()
            ->wherePivot('is_enabled', true)
            ->where('modules.is_active', true)
            ->pluck('modules.key')
            ->all();
    }
}
