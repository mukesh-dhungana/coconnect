<?php

namespace App\Http\Controllers\Api;

use App\Domain\Rbac\Support\RbacAudit;
use App\Http\Controllers\Controller;
use App\Http\Requests\AuditQueryRequest;
use App\Support\Concerns\RespondsWithJson;
use Illuminate\Http\JsonResponse;

class AuditController extends Controller
{
    use RespondsWithJson;

    /** The access-control ledger: who changed what, when, and why. */
    public function index(AuditQueryRequest $request): JsonResponse
    {
        $data  = $request->validated();
        $query = RbacAudit::query()->with('causer');

        if (! empty($data['event'])) {
            $query->where('event', $data['event']);
        }

        if (! empty($data['account_id'])) {
            $query->where('properties->account_id', (int) $data['account_id']);
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
