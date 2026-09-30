<?php

use App\Providers\ApiDocsServiceProvider;
use App\Providers\AppServiceProvider;
use App\Providers\DomainServiceProvider;

return [
    AppServiceProvider::class,
    DomainServiceProvider::class,
    ApiDocsServiceProvider::class,
];
