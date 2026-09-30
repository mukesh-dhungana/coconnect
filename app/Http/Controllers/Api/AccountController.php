<?php

namespace App\Http\Controllers\Api;

use App\Domain\Identity\Models\Account;
use App\Domain\Rbac\Models\Module;
use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Domain\Rbac\Support\RbacAudit;
use App\Http\Controllers\Controller;
use App\Http\Requests\StoreAccountRequest;
use App\Http\Requests\UpdateAccountRequest;
use App\Support\Concerns\RespondsWithJson;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

/**
 * Accounts -- the tenants themselves.
 *
 * Reading is open to anyone inside the account (`tenant` refuses the rest).
 * Creating, changing and deleting one is platform administration, guarded by
 * system.account_manage, which no role carries: in practice, super
 * administrators only.
 */
class AccountController extends Controller
{
    use RespondsWithJson;

    /**
     * Accounts and their locations -- drives the scope pickers. A super
     * administrator sees every account; anyone else only the ones they hold
     * a live grant in, so one client never learns another's name.
     */
    public function index(Request $request): JsonResponse
    {
        $user = $request->user();

        $accounts = Account::with('locations:id,account_id,name')
            ->unless($user->is_admin, fn ($q) => $q->whereIn('id',
                $user->roleAssignments()->active()->select('account_id')))
            ->orderBy('name')
            ->get();

        return $this->ok($accounts->map(fn (Account $a) => $this->present($a)));
    }

    /** Archived (soft-deleted) accounts, newest first -- platform administration only. */
    public function archived(): JsonResponse
    {
        return $this->ok(Account::onlyTrashed()->latest('deleted_at')->get()
            ->map(fn (Account $a) => $this->present($a->setRelation('locations', collect()))));
    }

    public function show(Account $account): JsonResponse
    {
        return $this->ok($this->present($account->load('locations:id,account_id,name')));
    }

    /**
     * Create an account with every module attached: core modules on, the rest
     * off until the client licenses them. Without the core module rows even a
     * super administrator could not administer the account, because a module
     * the account has not enabled is denied to everyone.
     */
    public function store(StoreAccountRequest $request): JsonResponse
    {
        $account = DB::transaction(function () use ($request) {
            $account = Account::create($request->validated());

            foreach (Module::all() as $module) {
                $account->modules()->attach($module->id, [
                    'is_enabled' => $module->is_core,
                    'enabled_at' => $module->is_core ? now() : null,
                ]);
            }

            return $account;
        });

        RbacAudit::record('account.created', $account, [
            'account' => $account->name,
            'account_id' => $account->id,
        ]);

        return $this->created($this->present($account->load('locations:id,account_id,name')));
    }

    public function update(UpdateAccountRequest $request, Account $account): JsonResponse
    {
        $account->fill($request->validated());
        $changes = $account->getDirty();
        $account->save();

        RbacAudit::record('account.updated', $account, [
            'account' => $account->name,
            'account_id' => $account->id,
            'changes' => $changes,
        ]);

        return $this->ok($this->present($account->load('locations:id,account_id,name')));
    }

    /**
     * Soft-deletes, and only an empty account: no live locations and no live
     * grants. Deleting one with people still in it would strand their access
     * rather than revoke it, and leave no record of who lost what.
     */
    public function destroy(Account $account): JsonResponse
    {
        if ($account->locations()->exists()) {
            return $this->failed('Delete this account\'s locations first.', 422);
        }

        if (UserRoleAssignment::outstanding()->where('account_id', $account->id)->exists()) {
            return $this->failed('Revoke every role granted in this account first.', 422);
        }

        $account->delete();

        RbacAudit::record('account.deleted', $account, [
            'account' => $account->name,
            'account_id' => $account->id,
        ]);

        return $this->noContent();
    }

    /**
     * Brings an archived account back. Its locations stay archived -- archiving
     * required them gone first -- and nobody regains access: every grant was
     * revoked before the archive, so access is granted again on the record.
     */
    public function restore(int $archived): JsonResponse
    {
        $account = Account::onlyTrashed()->findOrFail($archived);

        if (Account::where('slug', $account->slug)->exists()) {
            return $this->failed("Another account now uses the slug \"{$account->slug}\". Change one of them first.", 422);
        }

        $account->restore();

        RbacAudit::record('account.restored', $account, [
            'account' => $account->name,
            'account_id' => $account->id,
        ]);

        return $this->ok($this->present($account->load('locations:id,account_id,name')));
    }

    private function present(Account $account): array
    {
        return [
            'id'        => $account->id,
            'name'      => $account->name,
            'slug'      => $account->slug,
            'abn'       => $account->abn,
            'timezone'  => $account->timezone,
            'locale'    => $account->locale,
            'archived_at' => $account->deleted_at?->toIso8601String(),
            'locations' => $account->locations->map(fn ($l) => ['id' => $l->id, 'name' => $l->name])->values(),
        ];
    }
}
