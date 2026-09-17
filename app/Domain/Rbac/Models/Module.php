<?php

namespace App\Domain\Rbac\Models;

use App\Domain\Identity\Models\Account;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Module extends Model
{
    use HasFactory, SoftDeletes;

    protected $fillable = ['key', 'name', 'description', 'icon', 'sort_order', 'is_core', 'is_active'];

    protected function casts(): array
    {
        return ['is_core' => 'boolean', 'is_active' => 'boolean'];
    }

    public function permissions()
    {
        return $this->hasMany(Permission::class);
    }

    public function accounts()
    {
        return $this->belongsToMany(Account::class, 'account_module')
            ->withPivot(['is_enabled', 'enabled_at', 'disabled_at'])
            ->withTimestamps();
    }

    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }
}
