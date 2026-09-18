<?php

namespace App\Support\Http;

use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Collection;

/**
 * One shape for every API response, so clients never have to guess.
 *
 *   success  { "data": …, "meta"?: … }
 *   failure  { "message": …, "errors"?: … }
 *
 * Kept as a small class rather than scattered response()->json() calls: the
 * envelope is a contract, and a contract with one implementation is easier to
 * change than forty.
 */
final class ApiResponse
{
    public static function ok(mixed $data = null, array $meta = [], int $status = 200): JsonResponse
    {
        $payload = ['data' => $data];

        if ($meta !== []) {
            $payload['meta'] = $meta;
        }

        return response()->json($payload, $status);
    }

    public static function created(mixed $data = null): JsonResponse
    {
        return self::ok($data, status: 201);
    }

    public static function noContent(): JsonResponse
    {
        return response()->json(null, 204);
    }

    /** A page of results, with the paginator's own metadata flattened out. */
    public static function paginated(LengthAwarePaginator $page, ?callable $map = null): JsonResponse
    {
        $items = Collection::make($page->items());

        return self::ok(
            $map ? $items->map($map)->values() : $items->values(),
            [
                'total'        => $page->total(),
                'per_page'     => $page->perPage(),
                'current_page' => $page->currentPage(),
                'last_page'    => $page->lastPage(),
            ],
        );
    }

    public static function error(string $message, int $status = 400, array $errors = []): JsonResponse
    {
        $payload = ['message' => $message];

        if ($errors !== []) {
            $payload['errors'] = $errors;
        }

        return response()->json($payload, $status);
    }
}
