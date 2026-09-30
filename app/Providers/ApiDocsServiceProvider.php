<?php

namespace App\Providers;

use Dedoc\Scramble\Scramble;
use Dedoc\Scramble\Support\Generator\OpenApi;
use Dedoc\Scramble\Support\Generator\Operation;
use Dedoc\Scramble\Support\Generator\Parameter;
use Dedoc\Scramble\Support\Generator\Schema;
use Dedoc\Scramble\Support\Generator\SecurityScheme;
use Dedoc\Scramble\Support\Generator\Types\IntegerType;
use Dedoc\Scramble\Support\RouteInfo;
use Illuminate\Support\ServiceProvider;

/**
 * OpenAPI docs at /docs/api (Scramble), generated from the routes and
 * FormRequests, so there are no annotations to keep in sync.
 *
 * Scramble is a dev dependency: without it installed (composer install
 * --no-dev) this provider does nothing. Outside APP_ENV=local the docs are
 * refused unless the viewApiDocs gate allows them, and none is defined.
 */
class ApiDocsServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        if (! class_exists(Scramble::class)) {
            return;
        }

        Scramble::configure()
            // Sanctum SPA auth: the session cookie, not a bearer token. The docs
            // page sends the XSRF-TOKEN cookie back as X-XSRF-TOKEN itself.
            ->withDocumentTransformers(function (OpenApi $openApi) {
                $openApi->secure(
                    SecurityScheme::apiKey('cookie', config('session.cookie'))
                        ->setDescription('Session cookie set by POST /v1/login. Log in from these docs and the browser sends it on every later request.')
                );
            })
            ->withOperationTransformers(function (Operation $operation, RouteInfo $routeInfo) {
                $middleware = $routeInfo->route->gatherMiddleware();

                if (! in_array('auth:sanctum', $middleware, true)) {
                    $operation->security = [];

                    return;
                }

                // `tenant` takes the account from {account} when the route has
                // one; everywhere else these headers pick it.
                if (in_array('tenant', $middleware, true)) {
                    $params = $routeInfo->route->parameterNames();

                    if (! in_array('account', $params, true)) {
                        $operation->addParameters([$this->header(
                            'X-Account-Id',
                            'Account to act inside. Optional if you hold roles in exactly one account; super admins must send it for account-scoped reads.',
                        )]);
                    }

                    if (! in_array('location', $params, true)) {
                        $operation->addParameters([$this->header(
                            'X-Location-Id',
                            'Location to check location-level permissions against.',
                        )]);
                    }
                }
            });
    }

    private function header(string $name, string $description): Parameter
    {
        return Parameter::make($name, 'header')
            ->setSchema(Schema::fromType(new IntegerType))
            ->description($description);
    }
}
