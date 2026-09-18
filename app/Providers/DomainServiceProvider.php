<?php

namespace App\Providers;

use App\Domain\Rbac\Contracts\RoleRepository;
use App\Domain\Rbac\Contracts\UserDirectory;
use App\Domain\Rbac\Repositories\EloquentRoleRepository;
use App\Domain\Rbac\Repositories\EloquentUserDirectory;
use App\Support\Tenancy\TenantContext;
use Illuminate\Support\ServiceProvider;

class DomainServiceProvider extends ServiceProvider
{
    /** Interface → implementation. The only place the binding is stated. */
    public array $bindings = [
        RoleRepository::class => EloquentRoleRepository::class,
        UserDirectory::class  => EloquentUserDirectory::class,
    ];

    public function register(): void
    {
        // One tenant per request lifecycle.
        $this->app->scoped(TenantContext::class);
    }
}
