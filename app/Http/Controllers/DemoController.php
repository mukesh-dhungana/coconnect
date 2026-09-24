<?php

namespace App\Http\Controllers;

use App\Domain\Identity\Models\Account;
use App\Domain\Rbac\Models\Module;
use App\Domain\Rbac\Models\Role;
use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Services\PermissionCatalog;
use Illuminate\Http\Request;

class DemoController extends Controller
{
    public function __construct(private PermissionCatalog $catalog) {}

    public function index(Request $request)
    {
        $accounts = Account::with('locations')->orderBy('name')->get();
        $accountId = $request->integer('account') ?: $accounts->first()?->id;
        $account = $accounts->firstWhere('id', $accountId) ?? $accounts->first();

        $moduleState = $account->modules()->get()->keyBy('id');
        $modules = Module::active()->orderBy('sort_order')->get()->map(fn ($m) => (object) [
            'model'      => $m,
            'is_enabled' => (bool) ($moduleState[$m->id]->pivot->is_enabled ?? false),
        ]);

        // Module keys that are OFF for the selected account. The role catalogue
        // below uses this to show which of a role's permissions are inert here:
        // a role still *carries* travel.book, it simply does not resolve for an
        // account that has not enabled Travel.
        $disabledModuleKeys = $modules->filter(fn ($m) => ! $m->is_enabled)
            ->pluck('model.key')->all();

        $users = User::with([
            'roleAssignments.role', 'roleAssignments.account', 'roleAssignments.location',
        ])->orderBy('first_name')->get();

        $matrix = $users->map(function (User $u) use ($account) {
            $active = $u->roleAssignments->filter(fn ($a) => $a->is_active);

            return (object) [
                'user'        => $u,
                'assignments' => $u->roleAssignments->sortByDesc('created_at'),
                'roleCount'   => $active->count(),
                'permCount'   => count($this->catalog->permissionNames($u)),
                'modules'     => $this->catalog->visibleModules($u, $account->id),
            ];
        });

        return view('demo', [
            'accounts'  => $accounts,
            'account'   => $account,
            'modules'   => $modules,
            'matrix'    => $matrix,
            'roles'     => Role::with('permissions.module')->orderBy('scope_level')->orderBy('name')->get(),
            'disabledModuleKeys' => $disabledModuleKeys,
            'checkUser' => $request->integer('check_user') ?: $users->first()?->id,
        ]);
    }

    public function check(Request $request)
    {
        $data = $request->validate([
            'user_id'     => ['required', 'exists:users,id'],
            'permission'  => ['required', 'string'],
            'account_id'  => ['nullable', 'integer'],
            'location_id' => ['nullable', 'integer'],
        ]);

        $user = User::findOrFail($data['user_id']);

        return response()->json([
            'allowed' => $user->hasPermission(
                $data['permission'],
                $data['account_id'] ?: null,
                $data['location_id'] ?: null,
            ),
        ]);
    }

    public function toggleModule(Request $request, Account $account, Module $module)
    {
        if ($module->is_core) {
            return back()->with('error', "{$module->name} is a core module and cannot be disabled.");
        }

        $enabled = ! (bool) $account->modules()->where('modules.id', $module->id)->first()?->pivot?->is_enabled;

        $account->modules()->syncWithoutDetaching([
            $module->id => [
                'is_enabled'  => $enabled,
                'enabled_at'  => $enabled ? now() : null,
                'disabled_at' => $enabled ? null : now(),
            ],
        ]);

        cache()->forget("rbac:module:{$account->id}:{$module->key}");

        return back()->with('status', "{$module->name} ".($enabled ? 'enabled' : 'disabled')." for {$account->name}.");
    }
}
