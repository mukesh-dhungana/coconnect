<?php

namespace App\Domain\Rbac\Models;

use App\Domain\Identity\Models\Account;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Role extends Model
{
    use SoftDeletes;

    public const SCOPE_GLOBAL   = 'global';
    public const SCOPE_ACCOUNT  = 'account';
    public const SCOPE_LOCATION = 'location';

    protected $fillable = ['account_id', 'key', 'name', 'description', 'scope_level', 'is_system'];

    protected function casts(): array
    {
        return ['is_system' => 'boolean'];
    }

    public function permissions()
    {
        return $this->belongsToMany(Permission::class);
    }

    public function account()
    {
        return $this->belongsTo(Account::class);
    }

    public function assignments()
    {
        return $this->hasMany(UserRoleAssignment::class);
    }

    /** System roles (account_id null) plus this account's own roles. */
    public function scopeAvailableTo($query, ?int $accountId)
    {
        return $query->where(fn ($q) => $q->whereNull('account_id')->orWhere('account_id', $accountId));
    }
}
