<?php

namespace App\Http\Controllers\Api;

use App\Domain\Rbac\Support\RbacAudit;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class AuditController extends Controller
{
    /** The access-control ledger: who changed what, when, and why. */
    public function index(Request $request)
    {
        $data = $request->validate([
            'event'      => ['nullable', 'string'],
            'account_id' => ['nullable', 'integer'],
            'per_page'   => ['nullable', 'integer', 'min:1', 'max:100'],
        ]);

        $query = RbacAudit::query()->with('causer');

        if (! empty($data['event'])) {
            $query->where('event', $data['event']);
        }

        if (! empty($data['account_id'])) {
            $query->where('properties->account_id', (int) $data['account_id']);
        }

        $page = $query->paginate($data['per_page'] ?? 25);

        return response()->json([
            'data' => collect($page->items())->map(fn ($a) => [
                'id'         => $a->id,
                'event'      => $a->event,
                'actor'      => $a->causer?->name ?? 'system',
                'subject'    => class_basename($a->subject_type ?? ''),
                'subject_id' => $a->subject_id,
                'properties' => $a->properties,
                'at'         => $a->created_at?->toIso8601String(),
            ])->values(),
            'meta' => [
                'total'        => $page->total(),
                'current_page' => $page->currentPage(),
                'last_page'    => $page->lastPage(),
            ],
        ]);
    }

    /** Distinct event types, for filter dropdowns. */
    public function events()
    {
        return response()->json(
            RbacAudit::query()->reorder()->distinct()->pluck('event')->filter()->values()
        );
    }
}
