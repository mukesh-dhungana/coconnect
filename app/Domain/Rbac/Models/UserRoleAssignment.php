<?php

namespace App\Domain\Rbac\Models;

use App\Domain\Identity\Models\Account;
use App\Domain\Identity\Models\Location;
use App\Domain\Identity\Models\User;
use Illuminate\Database\Eloquent\Model;

class UserRoleAssignment extends Model
{
    protected $fillable = [
        'user_id', 'role_id', 'scope_level', 'account_id', 'location_id',
        'granted_by', 'grant_reason', 'valid_from', 'valid_until',
        'revoked_at', 'revoked_by',
    ];

    protected function casts(): array
    {
        return [
            'valid_from'  => 'datetime',
            'valid_until' => 'datetime',
            'revoked_at'  => 'datetime',
        ];
    }

    public function user()     { return $this->belongsTo(User::class); }
    public function role()     { return $this->belongsTo(Role::class); }
    public function account()  { return $this->belongsTo(Account::class); }
    public function location() { return $this->belongsTo(Location::class); }
    public function grantedBy(){ return $this->belongsTo(User::class, 'granted_by'); }

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
        if ($this->revoked_at !== null) return false;
        if ($this->valid_from && $this->valid_from->isFuture()) return false;
        if ($this->valid_until && $this->valid_until->isPast()) return false;

        return true;
    }

    public function getStatusAttribute(): string
    {
        if ($this->revoked_at !== null) return 'revoked';
        if ($this->valid_from && $this->valid_from->isFuture()) return 'pending';
        if ($this->valid_until && $this->valid_until->isPast()) return 'expired';
        if ($this->valid_until) return 'temporary';

        return 'active';
    }
}
