<?php

namespace App\Domain\Rbac\Models;

use App\Domain\Identity\Models\Account;
use App\Domain\Identity\Models\Location;
use App\Domain\Identity\Models\User;
use Illuminate\Database\Eloquent\Model;
use Spatie\Permission\Support\Config;

/**
 * A readable model over Spatie's model_has_roles pivot.
 *
 * Spatie treats that table as a join and nothing more: attach and detach, no
 * history. This product needs it to answer "who had access in March, granted by
 * whom, and why" -- so the row carries an audit trail, and revocation sets
 * revoked_at instead of deleting.
 *
 * That is why assignRole() and removeRole() must never be called on a User.
 * removeRole() detaches, which deletes the row and the trail with it. Grants go
 * through GrantRole and RevokeRole; see the guard test in tests/Feature/RbacTest.
 */
class UserRoleAssignment extends Model
{
    protected $fillable = [
        'model_id', 'model_type', 'role_id', 'scope_level', 'account_id', 'location_id',
        'granted_by', 'grant_reason', 'valid_from', 'valid_until',
        'revoked_at', 'revoked_by',
    ];

    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        $this->table = Config::modelHasRolesTable();
    }

    protected function casts(): array
    {
        return [
            'valid_from' => 'datetime',
            'valid_until' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }

    public function user()
    {
        return $this->belongsTo(User::class, 'model_id');
    }

    public function role()
    {
        return $this->belongsTo(Role::class);
    }

    public function account()
    {
        return $this->belongsTo(Account::class);
    }

    public function location()
    {
        return $this->belongsTo(Location::class);
    }

    public function grantedBy()
    {
        return $this->belongsTo(User::class, 'granted_by');
    }

    /**
     * Active = not revoked, started, not expired.
     * Everything that resolves a permission goes through this scope.
     */
    public function scopeActive($query)
    {
        $now = now();

        return $query->whereNull('revoked_at')
            ->where(fn ($q) => $q->whereNull('valid_from')->orWhere('valid_from', '<=', $now))
            ->where(fn ($q) => $q->whereNull('valid_until')->orWhere('valid_until', '>', $now));
    }

    public function getIsActiveAttribute(): bool
    {
        if ($this->revoked_at !== null) {
            return false;
        }
        if ($this->valid_from && $this->valid_from->isFuture()) {
            return false;
        }
        if ($this->valid_until && $this->valid_until->isPast()) {
            return false;
        }

        return true;
    }

    public function getStatusAttribute(): string
    {
        if ($this->revoked_at !== null) {
            return 'revoked';
        }
        if ($this->valid_from && $this->valid_from->isFuture()) {
            return 'pending';
        }
        if ($this->valid_until && $this->valid_until->isPast()) {
            return 'expired';
        }
        if ($this->valid_until) {
            return 'temporary';
        }

        return 'active';
    }
}
