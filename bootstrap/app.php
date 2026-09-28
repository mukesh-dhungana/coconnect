<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        apiPrefix: 'api',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    // Domain commands live beside their module, not in app/Console/Commands,
    // so they are registered explicitly.
    ->withCommands([
        \App\Domain\Rbac\Console\BackfillLegacyRoles::class,
        \App\Domain\Rbac\Console\RecordExpiredGrants::class,
    ])
    ->withMiddleware(function (Middleware $middleware): void {
        // Sanctum SPA auth: the React app authenticates with the session
        // cookie, not a bearer token, so nothing sensitive sits in browser
        // storage.
        $middleware->statefulApi();

        $middleware->alias([
            // Spatie's own middleware. The scope it checks in is set by 'tenant'.
            'permission' => \Spatie\Permission\Middleware\PermissionMiddleware::class,
            'tenant'     => \App\Http\Middleware\ResolveTenant::class,
        ]);

        // Never redirect an unauthenticated API caller to a login page. Without
        // this, a browser hitting an API route with no Accept header gets a 500
        // ("Route [login] not defined") instead of a clean 401.
        $middleware->redirectGuestsTo(fn (Request $request) => $request->is('api/*')
            ? null
            : '/');
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        \App\Support\Http\ApiExceptionHandler::register($exceptions);
    })->create();
