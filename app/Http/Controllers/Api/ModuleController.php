<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Domain\Identity\Models\Account;
use App\Domain\Rbac\Models\Module;
use Illuminate\Http\Request;

class ModuleController extends Controller
{
    /** Every module in the catalogue. */
    public function index()
    {
        return response()->json(
            Module::active()->withCount('permissions')->orderBy('sort_order')->get()
        );
    }

    /** Create a module at runtime -- no deploy needed. */
    public function store(Request $request)
    {
        $data = $request->validate([
            'key'         => ['required', 'string', 'max:50', 'regex:/^[a-z][a-z0-9_]*$/', 'unique:modules,key'],
            'name'        => ['required', 'string', 'max:100'],
            'description' => ['nullable', 'string', 'max:255'],
            'icon'        => ['nullable', 'string', 'max:50'],
            'sort_order'  => ['nullable', 'integer', 'min:0', 'max:9999'],
        ]);

        return response()->json(Module::create($data), 201);
    }

    /** Which modules an account may use, and which are on. */
    public function forAccount(Account $account)
    {
        $enabled = $account->modules()->pluck('modules.id', 'modules.id');
        $pivot   = $account->modules()->get()->keyBy('id');

        return response()->json(
            Module::active()->orderBy('sort_order')->get()->map(fn ($m) => [
                'id'         => $m->id,
                'key'        => $m->key,
                'name'       => $m->name,
                'is_core'    => $m->is_core,
                'is_enabled' => (bool) ($pivot[$m->id]->pivot->is_enabled ?? false),
            ])
        );
    }

    /** Turn a module on or off for one account. Core modules cannot go off. */
    public function toggleForAccount(Request $request, Account $account, Module $module)
    {
        $data = $request->validate(['is_enabled' => ['required', 'boolean']]);

        if ($module->is_core && ! $data['is_enabled']) {
            return response()->json([
                'message' => "{$module->name} is a core module and cannot be disabled.",
            ], 422);
        }

        $account->modules()->syncWithoutDetaching([
            $module->id => [
                'is_enabled'  => $data['is_enabled'],
                'enabled_at'  => $data['is_enabled'] ? now() : null,
                'disabled_at' => $data['is_enabled'] ? null : now(),
            ],
        ]);

        cache()->forget("rbac:module:{$account->id}:{$module->key}");

        return response()->json(['module' => $module->key, 'is_enabled' => $data['is_enabled']]);
    }
}
