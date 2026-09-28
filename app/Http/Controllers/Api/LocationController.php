<?php

namespace App\Http\Controllers\Api;

use App\Domain\Identity\Models\Account;
use App\Domain\Identity\Models\Location;
use App\Domain\Rbac\Models\UserRoleAssignment;
use App\Domain\Rbac\Support\RbacAudit;
use App\Http\Controllers\Controller;
use App\Http\Requests\StoreLocationRequest;
use App\Http\Requests\UpdateLocationRequest;
use App\Support\Concerns\RespondsWithJson;
use Illuminate\Http\JsonResponse;

/**
 * Locations -- sites, villages and camps inside one account.
 *
 * Always addressed through their account (accounts/{account}/locations/...),
 * with scoped bindings, so a location id from another account is a 404 rather
 * than a quiet cross-tenant edit. Writes are guarded by
 * system.location_manage, which no role carries yet.
 */
class LocationController extends Controller
{
    use RespondsWithJson;

    public function index(Account $account): JsonResponse
    {
        return $this->ok($account->locations()->orderBy('name')->get()
            ->map(fn (Location $l) => $this->present($l)));
    }

    public function show(Account $account, Location $location): JsonResponse
    {
        return $this->ok($this->present($location));
    }

    public function store(StoreLocationRequest $request, Account $account): JsonResponse
    {
        $location = $account->locations()->create($request->validated());

        RbacAudit::record('location.created', $location, [
            'location' => $location->name,
            'location_id' => $location->id,
            'account_id' => $account->id,
        ]);

        return $this->created($this->present($location));
    }

    public function update(UpdateLocationRequest $request, Account $account, Location $location): JsonResponse
    {
        $location->fill($request->validated());
        $changes = $location->getDirty();
        $location->save();

        RbacAudit::record('location.updated', $location, [
            'location' => $location->name,
            'location_id' => $location->id,
            'account_id' => $account->id,
            'changes' => $changes,
        ]);

        return $this->ok($this->present($location));
    }

    /**
     * Soft-deletes, and only once nobody holds a live grant there -- the same
     * rule as for accounts: revoke access explicitly, so the audit trail says
     * who lost it.
     */
    public function destroy(Account $account, Location $location): JsonResponse
    {
        if (UserRoleAssignment::outstanding()->where('location_id', $location->id)->exists()) {
            return $this->failed('Revoke every role granted at this location first.', 422);
        }

        $location->delete();

        RbacAudit::record('location.deleted', $location, [
            'location' => $location->name,
            'location_id' => $location->id,
            'account_id' => $account->id,
        ]);

        return $this->noContent();
    }

    private function present(Location $location): array
    {
        return [
            'id'         => $location->id,
            'account_id' => $location->account_id,
            'name'       => $location->name,
            'slug'       => $location->slug,
            'suburb'     => $location->suburb,
            'state'      => $location->state,
        ];
    }
}
