<?php

namespace App\Support\Tenancy;

use App\Domain\Identity\Models\Account;

/**
 * The account every request is acting inside.
 *
 * Multi-tenancy here is **one database, shared schema, row-level isolation**:
 * every tenant-owned table carries account_id, and a global Eloquent scope
 * filters it. That is the right trade for this product — hundreds of accounts,
 * not hundreds of thousands, and cross-tenant reporting stays possible.
 *
 * The alternative, a schema or database per tenant, buys stronger isolation at
 * the cost of migrations running N times and connection juggling. It is not
 * worth it here, and nothing in this design forecloses it later.
 */
final class TenantContext
{
    private ?Account $account = null;

    /** Set when a block of work must cross tenants (console, jobs, admin). */
    private bool $unscoped = false;

    public function set(Account $account): void
    {
        $this->account = $account;
    }

    public function get(): ?Account
    {
        return $this->account;
    }

    public function id(): ?int
    {
        return $this->account?->id;
    }

    public function has(): bool
    {
        return $this->account !== null && ! $this->unscoped;
    }

    public function clear(): void
    {
        $this->account = null;
    }

    /**
     * Run a callback with tenant filtering switched off.
     *
     * Deliberately explicit and deliberately awkward to reach: every use is a
     * decision to read across tenants, and should read like one.
     */
    public function withoutScope(callable $callback): mixed
    {
        $previous = $this->unscoped;
        $this->unscoped = true;

        try {
            return $callback();
        } finally {
            $this->unscoped = $previous;
        }
    }

    public function isUnscoped(): bool
    {
        return $this->unscoped;
    }
}
