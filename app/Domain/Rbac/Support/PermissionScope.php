<?php

namespace App\Domain\Rbac\Support;

use Closure;
use Spatie\Permission\PermissionRegistrar;

/**
 * The account and location every Spatie permission check is answered for.
 *
 * The account IS Spatie's team: it lives on the PermissionRegistrar, exactly
 * as setPermissionsTeamId() leaves it, so Spatie's own roles() filtering sees
 * it. Location is the second dimension Spatie has no slot for, so it is held
 * here and read by User::roles().
 *
 * ResolveTenant sets both once per request. Code that must ask about some
 * other scope -- "may this person do X at site Y?" -- uses within(), which
 * puts the previous scope back afterwards.
 */
final class PermissionScope
{
    private ?int $locationId = null;

    public function __construct(private PermissionRegistrar $registrar) {}

    public function set(?int $accountId, ?int $locationId = null): void
    {
        $this->registrar->setPermissionsTeamId($accountId);
        $this->locationId = $accountId === null ? null : $locationId;
    }

    public function accountId(): ?int
    {
        $id = $this->registrar->getPermissionsTeamId();

        return $id === null ? null : (int) $id;
    }

    public function locationId(): ?int
    {
        return $this->locationId;
    }

    /**
     * Run a check against another scope, then restore the current one --
     * including null. Spatie's team is static state, so a check that did not
     * restore it would leak into every later check in the request.
     */
    public function within(?int $accountId, ?int $locationId, Closure $callback): mixed
    {
        $previous = [$this->accountId(), $this->locationId];

        $this->set($accountId, $locationId);

        try {
            return $callback();
        } finally {
            $this->set(...$previous);
        }
    }
}
