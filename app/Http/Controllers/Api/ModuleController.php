<?php

namespace App\Http\Controllers\Api;

use App\Domain\Identity\Models\Account;
use App\Domain\Rbac\Models\Module;
use App\Domain\Rbac\Services\PermissionCatalog;
use App\Domain\Rbac\Support\RbacAudit;
use App\Http\Controllers\Controller;
use App\Http\Requests\StoreModuleRequest;
use App\Http\Requests\ToggleModuleRequest;
use App\Support\Concerns\RespondsWithJson;
use Illuminate\Http\JsonResponse;

class ModuleController extends Controller
{
    use RespondsWithJson;

    /** Every module in the catalogue. */
    public function index(): JsonResponse
    {
        return $this->ok(
            Module::active()->withCount('permissions')->orderBy('sort_order')->get()
        );
    }

    /** Create a module at runtime — no deploy needed. */
    public function store(StoreModuleRequest $request): JsonResponse
    {
        $module = Module::create($request->validated());

        RbacAudit::record('module.created', $module, [
            'module' => $module->key, 'name' => $module->name,
        ]);

        return $this->created($module);
    }

    /** Which modules an account may use, and which are on. */
    public function forAccount(Account $account): JsonResponse
    {
        $pivot = $account->modules()->get()->keyBy('id');

        return $this->ok(
            Module::active()->orderBy('sort_order')->get()->map(fn ($m) => [
                'id' => $m->id,
                'key' => $m->key,
                'name' => $m->name,
                'is_core' => $m->is_core,
                'is_enabled' => (bool) ($pivot[$m->id]->pivot->is_enabled ?? false),
            ])
        );
    }

    /** Turn a module on or off for one account. Core modules cannot go off. */
    public function toggleForAccount(ToggleModuleRequest $request, Account $account, Module $module): JsonResponse
    {
        $enabled = $request->boolean('is_enabled');

        if ($module->is_core && ! $enabled) {
            return $this->failed("{$module->name} is a core module and cannot be disabled.", 422);
        }

        $account->modules()->syncWithoutDetaching([
            $module->id => [
                'is_enabled' => $enabled,
                'enabled_at' => $enabled ? now() : null,
                'disabled_at' => $enabled ? null : now(),
            ],
        ]);

        app(PermissionCatalog::class)->flushModule($module->key, $account->id);

        RbacAudit::record($enabled ? 'module.enabled' : 'module.disabled', $module, [
            'account' => $account->name,
            'account_id' => $account->id,
            'module' => $module->key,
        ]);

        return $this->ok(['module' => $module->key, 'is_enabled' => $enabled]);
    }
}
