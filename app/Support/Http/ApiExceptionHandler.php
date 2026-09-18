<?php

namespace App\Support\Http;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Throwable;

/**
 * API errors answer with a plain JSON object and nothing else.
 *
 * Laravel's default renders a stack trace when APP_DEBUG is on, which leaks
 * absolute filesystem paths and framework internals to anyone who can reach
 * the endpoint. That is fine for a Blade page a developer is staring at; it
 * is not fine for an API. Debug detail stays in the log, where it belongs.
 */
final class ApiExceptionHandler
{
    public static function register(Exceptions $exceptions): void
    {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson()
        );

        $exceptions->render(function (Throwable $e, Request $request) {
            if (! $request->is('api/*') && ! $request->expectsJson()) {
                return null;   // let web routes render normally
            }

            return self::toResponse($e);
        });
    }

    private static function toResponse(Throwable $e)
    {
        return match (true) {
            $e instanceof ValidationException => ApiResponse::error(
                'The given data was invalid.', 422, $e->errors()
            ),

            $e instanceof AuthenticationException => ApiResponse::error(
                'Unauthenticated.', 401
            ),

            $e instanceof AuthorizationException => ApiResponse::error(
                $e->getMessage() ?: 'This action is unauthorized.', 403
            ),

            // Route-model binding misses look like a missing record, not a
            // missing route — say so without naming the model class.
            $e instanceof ModelNotFoundException => ApiResponse::error(
                'Record not found.', 404
            ),

            $e instanceof NotFoundHttpException => ApiResponse::error(
                'Endpoint not found.', 404
            ),

            $e instanceof MethodNotAllowedHttpException => ApiResponse::error(
                'Method not allowed for this endpoint.', 405
            ),

            $e instanceof HttpExceptionInterface => ApiResponse::error(
                $e->getMessage() ?: 'Request failed.', $e->getStatusCode()
            ),

            // Anything unhandled: a generic message. The real exception is
            // already on its way to the log and to Bugsnag.
            default => ApiResponse::error(
                config('app.debug')
                    ? $e->getMessage()          // message only, never the trace
                    : 'Something went wrong.',
                500
            ),
        };
    }
}
