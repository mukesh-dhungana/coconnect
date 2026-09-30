<?php

use App\Http\Controllers\Api\AccountController;
use App\Http\Controllers\Api\AssignmentController;
use App\Http\Controllers\Api\AuditController;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\LocationController;
use App\Http\Controllers\Api\ModuleController;
use App\Http\Controllers\Api\RoleController;
use App\Http\Controllers\Api\UserController;
use Illuminate\Support\Facades\Route;

/*
| RBAC API — /api/v1
|
| Sanctum SPA session auth: the React app calls /sanctum/csrf-cookie, then
| POST /api/v1/login. No tokens are stored in the browser.
|
| Administration is guarded three times: `auth:sanctum` proves who you are,
| `tenant` decides which account the request acts inside (and refuses one you
| hold no grant in), and `permission:<name>` asks whether you may
| do it there -- Spatie's PermissionMiddleware, answering for the account and
| location `tenant` put in scope.
*/

Route::prefix('v1')->group(function () {

    // ---- Public ----------------------------------------------------------
    Route::post('login', [AuthController::class, 'login'])->middleware('throttle:6,1');

    // ---- Authenticated ---------------------------------------------------
    Route::middleware(['auth:sanctum', 'tenant'])->group(function () {
        Route::post('logout', [AuthController::class, 'logout']);
        Route::get('me', [AuthController::class, 'me']);

        // Reference data any signed-in admin screen needs. accounts lists only
        // the caller's own; the {account} reads are refused by `tenant` for
        // an account the caller holds no grant in.
        Route::get('accounts', [AccountController::class, 'index']);
        // Numeric only, so accounts/archived below is not read as an account id.
        Route::get('accounts/{account}', [AccountController::class, 'show'])->whereNumber('account');
        Route::get('accounts/{account}/locations', [LocationController::class, 'index']);
        Route::get('accounts/{account}/locations/{location}', [LocationController::class, 'show'])->scopeBindings();
        Route::get('permissions', [UserController::class, 'permissions']);

        // Reading the model requires the audit-view permission, which every
        // administrative role carries.
        Route::middleware('permission:system.audit_view')->group(function () {
            Route::get('modules', [ModuleController::class, 'index']);
            Route::get('accounts/{account}/modules', [ModuleController::class, 'forAccount']);
            Route::get('roles', [RoleController::class, 'index']);
            Route::get('users', [UserController::class, 'index']);
            Route::get('users/{user}/assignments', [AssignmentController::class, 'index']);
            Route::get('users/{user}/check', [AssignmentController::class, 'check']);
            Route::get('audit', [AuditController::class, 'index']);
            Route::get('audit/events', [AuditController::class, 'events']);
        });

        // Changing the model requires configuration rights: platform-level,
        // so in practice only a super administrator.
        Route::middleware('permission:system.integration_manage')->group(function () {
            Route::post('modules', [ModuleController::class, 'store']);
            Route::put('accounts/{account}/modules/{module}', [ModuleController::class, 'toggleForAccount']);
            Route::post('roles', [RoleController::class, 'store']);
            Route::put('roles/{role}/permissions', [RoleController::class, 'syncPermissions']);
        });

        // Accounts and locations. Platform administration: no role carries
        // either permission, so in practice super administrators only.
        // Scoped bindings make a location from another account a 404.
        // DELETE archives (soft-deletes); archived accounts are listed and
        // restored here. {archived} is not {account} on purpose: `tenant`
        // resolves {account} and would 404 an archived one.
        Route::middleware('permission:system.account_manage')->group(function () {
            Route::get('accounts/archived', [AccountController::class, 'archived']);
            Route::post('accounts', [AccountController::class, 'store']);
            Route::put('accounts/{account}', [AccountController::class, 'update']);
            Route::delete('accounts/{account}', [AccountController::class, 'destroy']);
            Route::post('accounts/{archived}/restore', [AccountController::class, 'restore'])->whereNumber('archived');
        });

        Route::middleware('permission:system.location_manage')->scopeBindings()->group(function () {
            Route::post('accounts/{account}/locations', [LocationController::class, 'store']);
            Route::put('accounts/{account}/locations/{location}', [LocationController::class, 'update']);
            Route::delete('accounts/{account}/locations/{location}', [LocationController::class, 'destroy']);
        });

        // Adding and editing personnel and managing their roles. A super
        // administrator holds this everywhere; a Site Administrator only in
        // their own account -- `tenant` puts that account in scope, and the
        // controllers refuse anyone outside it. Operational roles never carry it.
        Route::middleware('permission:system.user_manage')->group(function () {
            Route::post('users', [UserController::class, 'store']);
            Route::put('users/{user}', [UserController::class, 'update']);
            Route::post('users/{user}/assignments', [AssignmentController::class, 'store']);
            Route::delete('assignments/{assignment}', [AssignmentController::class, 'destroy']);
        });
    });
});
