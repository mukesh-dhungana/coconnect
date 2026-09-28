<?php

namespace App\Http\Controllers\Api;

use App\Domain\Rbac\Support\RbacAudit;
use App\Http\Controllers\Controller;
use App\Http\Requests\AuditQueryRequest;
use App\Support\Concerns\RespondsWithJson;
use App\Support\Tenancy\TenantContext;
use Illuminate\Http\JsonResponse;

class AuditController extends Controller
{
    use RespondsWithJson;

    public function __construct(private TenantContext $tenant) {}

    /**
     * The access-control ledger: who changed what, when, and why.
     *
     * A super administrator reads all of it, optionally filtered to one
     * account. Anyone else reads only the account the request acts in -- the
     * ledger names people, so an unfiltered read would list another client's
     * users.
     */
    public function index(AuditQueryRequest $request): JsonResponse
    {
        $data  = $request->validated();
        $query = RbacAudit::query()->with('causer');

        if (! empty($data['event'])) {
            $query->where('event', $data['event']);
        }

        $accountId = $request->user()->is_admin
            ? ($data['account_id'] ?? null)
            : $this->tenant->id();

        if (! empty($accountId)) {
            $query->where('properties->account_id', (int) $accountId);
        }

        $page = $query->paginate($data['per_page'] ?? 25);

        return $this->paginated($page, fn ($a) => [
            'id'         => $a->id,
            'event'      => $a->event,
            'actor'      => $a->causer?->name ?? 'system',
            'subject'    => class_basename($a->subject_type ?? ''),
            'subject_id' => $a->subject_id,
            'properties' => $a->properties,
            'at'         => $a->created_at?->toIso8601String(),
        ]);
    }

    /** Distinct event types, for filter dropdowns. */
    public function events(): JsonResponse
    {
        return $this->ok(
            RbacAudit::query()->reorder()->distinct()->pluck('event')->filter()->values()
        );
    }
}
