<?php

namespace App\Domain\Identity\Models;

use App\Domain\Rbac\Models\Role;
use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Domain\Rbac\Services\PermissionResolver;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable
{
    use Notifiable, SoftDeletes;

    protected $fillable = [
        'first_name', 'last_name', 'uuid', 'email', 'mobile', 'mobile_country',
        'password', 'is_admin', 'timezone', 'language',
    ];

    protected $hidden = ['password', 'remember_token'];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'last_seen_at'      => 'datetime',
            'password'          => 'hashed',
            'is_admin'          => 'boolean',
        ];
    }

    public function getNameAttribute(): string
    {
        return trim("{$this->first_name} {$this->last_name}");
    }

    public function roleAssignments()
    {
        return $this->hasMany(UserRoleAssignment::class);
    }

    public function accounts()
    {
        return $this->belongsToMany(Account::class, 'account_user')
            ->withPivot(['roster', 'workgroup', 'employer', 'type', 'role'])
            ->withTimestamps();
    }

    /** Roles held right now, across every scope. A user may hold many. */
    public function activeRoles()
    {
        return $this->belongsToMany(Role::class, 'user_role_assignments')
            ->wherePivotNull('revoked_at')
            ->withPivot(['scope_level', 'account_id', 'location_id', 'valid_until']);
    }

    public function can($abilities, $arguments = [])
    {
        // Keep Laravel's Gate behaviour for policy-style checks.
        if (! is_string($abilities) || ! str_contains($abilities, '.')) {
            return parent::can($abilities, $arguments);
        }

        $accountId  = $arguments['account'] ?? $arguments[0] ?? null;
        $locationId = $arguments['location'] ?? $arguments[1] ?? null;

        return app(PermissionResolver::class)->allows($this, $abilities, $accountId, $locationId);
    }

    public function hasPermission(string $permission, ?int $accountId = null, ?int $locationId = null): bool
    {
        return app(PermissionResolver::class)->allows($this, $permission, $accountId, $locationId);
    }
}
