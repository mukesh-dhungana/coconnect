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
    ])
    ->withMiddleware(function (Middleware $middleware): void {
        // Sanctum SPA auth: the React app authenticates with the session
        // cookie, not a bearer token, so nothing sensitive sits in browser
        // storage.
        $middleware->statefulApi();

        $middleware->alias([
            'permission' => \App\Http\Middleware\EnsurePermission::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
    })->create();
