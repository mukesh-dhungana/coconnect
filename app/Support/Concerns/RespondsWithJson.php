<?php

namespace App\Support\Concerns;

use App\Support\Http\ApiResponse;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Http\JsonResponse;

/**
 * Sugar so controllers read as intent rather than plumbing:
 *
 *   return $this->ok($roles);
 *   return $this->created($user);
 *   return $this->failed('System is a core module.', 422);
 */
trait RespondsWithJson
{
    protected function ok(mixed $data = null, array $meta = []): JsonResponse
    {
        return ApiResponse::ok($data, $meta);
    }

    protected function created(mixed $data = null): JsonResponse
    {
        return ApiResponse::created($data);
    }

    protected function noContent(): JsonResponse
    {
        return ApiResponse::noContent();
    }

    protected function paginated(LengthAwarePaginator $page, ?callable $map = null): JsonResponse
    {
        return ApiResponse::paginated($page, $map);
    }

    protected function failed(string $message, int $status = 400, array $errors = []): JsonResponse
    {
        return ApiResponse::error($message, $status, $errors);
    }
}
