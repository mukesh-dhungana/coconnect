<?php

namespace App\Domain\Identity\Models;

use App\Domain\Rbac\Models\Role;
use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Domain\Rbac\Services\PermissionResolver;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Spatie\Permission\Traits\HasRoles;

class User extends Authenticatable
{
    use HasRoles, Notifiable, SoftDeletes;

    protected $fillable = [
        'first_name', 'last_name', 'uuid', 'email', 'mobile', 'mobile_country',
        'password', 'is_admin', 'timezone', 'language',
    ];

    protected $hidden = ['password', 'remember_token'];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'password' => 'hashed',
            // Super administrator: every permission, in every account, always.
            // This is the 'global' scope level -- it is a flag rather than a
            // role because Spatie pins each assignment to exactly one team, so
            // an account-independent grant cannot be stored. Honoured in
            // AppServiceProvider's Gate::before.
            'is_admin' => 'boolean',
        ];
    }

    public function getNameAttribute(): string
    {
        return trim("{$this->first_name} {$this->last_name}");
    }

    public function roleAssignments()
    {
        return $this->hasMany(UserRoleAssignment::class, 'model_id')
            ->where('model_type', static::class);
    }

    public function accounts()
    {
        return $this->belongsToMany(Account::class, 'account_user')
            ->withPivot(['roster', 'workgroup', 'employer', 'type', 'role'])
            ->withTimestamps();
    }

    /**
     * Spatie's roles(), narrowed to the grants that actually apply right now.
     *
     * roles() has already filtered to the account set by setPermissionsTeamId.
     * Three things it cannot know about are added here:
     *
     *   location  -- null on the pivot means every location in the account, so
     *                an account-wide grant answers a question about location L
     *                while a grant at another location does not
     *   revoked   -- Spatie deletes on removeRole; this app keeps the row
     *   validity  -- valid_from/valid_until carry temporary elevation
     *
     * Queried fresh rather than read off a loaded relation: Spatie keeps the
     * active team in static state, and a cached ->roles collection from a
     * previous account would silently answer for the wrong tenant.
     *
     * @return Collection<int, Role>
     */
    public function scopedRoles(?int $locationId = null): Collection
    {
        $now = now();
        $table = (new UserRoleAssignment)->getTable();

        return $this->roles()
            ->with('permissions:id,name')
            ->whereNull("{$table}.revoked_at")
            ->where(fn ($q) => $q->whereNull("{$table}.valid_from")->orWhere("{$table}.valid_from", '<=', $now))
            ->where(fn ($q) => $q->whereNull("{$table}.valid_until")->orWhere("{$table}.valid_until", '>', $now))
            ->where(function ($q) use ($table, $locationId) {
                $q->whereNull("{$table}.location_id");

                if ($locationId !== null) {
                    $q->orWhere("{$table}.location_id", $locationId);
                }
            })
            ->get();
    }

    public function hasPermission(string $permission, ?int $accountId = null, ?int $locationId = null): bool
    {
        return app(PermissionResolver::class)->allows($this, $permission, $accountId, $locationId);
    }
}
