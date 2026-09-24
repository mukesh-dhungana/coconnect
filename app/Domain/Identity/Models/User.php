<?php

namespace App\Domain\Identity\Models;

use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Domain\Rbac\Services\PermissionCatalog;
use App\Domain\Rbac\Support\PermissionScope;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Spatie\Permission\Support\Config;
use Spatie\Permission\Traits\HasRoles;

class User extends Authenticatable
{
    use HasRoles {
        roles as protected spatieRoles;
        hasPermissionTo as protected spatieHasPermissionTo;
    }
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
            'last_seen_at' => 'datetime',
            'password' => 'hashed',
            // Super administrator: every permission, in every account, always.
            // This is the 'global' scope level -- it is a flag rather than a
            // role because Spatie pins each assignment to exactly one team, so
            // an account-independent grant cannot be stored. Honoured in
            // hasPermissionTo() below.
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
     * Every Spatie read -- hasPermissionTo(), can(), hasRole(), the permission
     * middleware -- goes through this relation, so filtering here is what makes
     * the package's own API scope-correct. Spatie has already narrowed it to
     * the active team (the account). Three things it cannot know about:
     *
     *   location  -- null on the pivot means every location in the account, so
     *                an account-wide grant answers a question about location L
     *                while a grant at another location does not. With no
     *                location in scope, only account-wide grants count.
     *   revoked   -- Spatie deletes on removeRole; this app keeps the row
     *   validity  -- valid_from/valid_until carry temporary elevation
     *
     * These are plain where() clauses, not wherePivot(), on purpose: they
     * filter reads only, so Spatie's detach() on force-delete still removes
     * every row rather than just the live ones.
     */
    public function roles(): BelongsToMany
    {
        $now = now();
        $table = Config::modelHasRolesTable();
        $locationId = app(PermissionScope::class)->locationId();

        return $this->spatieRoles()
            ->whereNull("{$table}.revoked_at")
            ->where(fn ($q) => $q->whereNull("{$table}.valid_from")->orWhere("{$table}.valid_from", '<=', $now))
            ->where(fn ($q) => $q->whereNull("{$table}.valid_until")->orWhere("{$table}.valid_until", '>', $now))
            ->where(function ($q) use ($table, $locationId) {
                $q->whereNull("{$table}.location_id");

                if ($locationId !== null) {
                    $q->orWhere("{$table}.location_id", $locationId);
                }
            });
    }

    /**
     * Spatie's hasPermissionTo(), with the two rules that sit above roles.
     *
     *   1. The permission's MODULE must be enabled for the account in scope.
     *      That is a commercial boundary, so it is checked first -- before the
     *      super-admin flag. A module the client has not bought stays shut
     *      even for staff; moving is_admin above it would quietly sell it.
     *   2. users.is_admin is the global scope level: every permission, every
     *      account. Spatie pins each assignment to one team, so "everywhere"
     *      is a flag rather than a grant.
     *
     * Then Spatie answers from roles() above. The loaded relation is dropped
     * first: Spatie caches it on the model, and a collection loaded for another
     * account, location or moment would answer for the wrong one. Spatie's own
     * cache (which roles carry which permission) is untouched.
     *
     * An unknown permission throws PermissionDoesNotExist, as in Spatie;
     * can() and checkPermissionTo() turn that into "no".
     */
    public function hasPermissionTo($permission, ?string $guardName = null): bool
    {
        $permission = $this->filterPermission($permission, $guardName);
        $accountId = app(PermissionScope::class)->accountId();

        if (! app(PermissionCatalog::class)->moduleAllows($permission->name, $accountId)) {
            return false;
        }

        if ($this->is_admin) {
            return true;
        }

        $this->unsetRelation('roles');

        return $this->spatieHasPermissionTo($permission, $guardName);
    }

    /**
     * Ask about a scope other than the current request's -- the "may this
     * person do X here?" question. Omitting the account keeps the current one.
     */
    public function hasPermission(string $permission, ?int $accountId = null, ?int $locationId = null): bool
    {
        $scope = app(PermissionScope::class);

        return $scope->within($accountId ?? $scope->accountId(), $locationId,
            fn () => $this->checkPermissionTo($permission));
    }
}
