<?php

namespace App\Support\Tenancy;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Applied to any model whose rows belong to exactly one account.
 *
 * Two jobs:
 *   1. Every query is filtered to the current tenant automatically, so a
 *      forgotten where() cannot leak another client's rows.
 *   2. account_id is stamped on create, so it cannot be forgotten either.
 *
 * Isolation that depends on developers remembering is not isolation.
 *
 * Deliberately NOT applied to:
 *   Role                 — account_id is nullable, and a NULL means "system
 *                          role, shared by every account". A tenant scope
 *                          would hide exactly the roles everyone needs.
 *   UserRoleAssignment   — the resolver has to see all of a person's grants
 *                          across every account to answer a question about
 *                          one of them.
 *   Account              — it is the tenant, not a tenant's property.
 */
trait BelongsToTenant
{
    public static function bootBelongsToTenant(): void
    {
        static::addGlobalScope('tenant', function (Builder $query) {
            $tenant = app(TenantContext::class);

            if ($tenant->has()) {
                $query->where($query->getModel()->getTable().'.account_id', $tenant->id());
            }
        });

        static::creating(function (Model $model) {
            $tenant = app(TenantContext::class);

            if ($tenant->has() && empty($model->account_id)) {
                $model->account_id = $tenant->id();
            }
        });
    }

    /** Escape hatch for a query that genuinely spans tenants. */
    public function scopeAcrossTenants(Builder $query): Builder
    {
        return $query->withoutGlobalScope('tenant');
    }
}
