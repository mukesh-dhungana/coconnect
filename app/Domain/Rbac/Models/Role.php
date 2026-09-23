<?php

namespace App\Domain\Rbac\Models;

use App\Domain\Identity\Models\Account;
use Illuminate\Database\Eloquent\SoftDeletes;
use Spatie\Permission\Models\Role as SpatieRole;

/**
 * Spatie's Role, with this product's two additions.
 *
 * account_id is Spatie's team key. Null means a system role available to every
 * account, which is both what this app meant by it before and what Spatie means
 * by a global role -- the two definitions coincide, so nothing is bent to fit.
 *
 * scope_level is ours. It records whether a role is granted per account or per
 * location, so GrantRole can reject a nonsense grant before the database has to.
 * There is no 'global' level: see users.is_admin and the Gate::before callback
 * in AppServiceProvider.
 */
class Role extends SpatieRole
{
    use SoftDeletes;

    public const SCOPE_ACCOUNT = 'account';

    public const SCOPE_LOCATION = 'location';

    protected $fillable = [
        'account_id', 'key', 'name', 'guard_name', 'description', 'scope_level', 'is_system',
    ];

    protected function casts(): array
    {
        return ['is_system' => 'boolean'];
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
