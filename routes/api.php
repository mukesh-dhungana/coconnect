<?php

use App\Http\Controllers\Api\AssignmentController;
use App\Http\Controllers\Api\AuditController;
use App\Http\Controllers\Api\AuthController;
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
| Administration is guarded twice: `auth:sanctum` proves who you are, and
| `permission:<name>` asks the resolver whether you may do it here. The
| resolver remains the single authority.
*/

Route::prefix('v1')->group(function () {

    // ---- Public ----------------------------------------------------------
    Route::post('login', [AuthController::class, 'login'])->middleware('throttle:6,1');

    // ---- Authenticated ---------------------------------------------------
    Route::middleware('auth:sanctum')->group(function () {
        Route::post('logout', [AuthController::class, 'logout']);
        Route::get('me', [AuthController::class, 'me']);

        // Reference data any signed-in admin screen needs
        Route::get('accounts', [UserController::class, 'accounts']);
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

        // Changing the model requires configuration rights.
        Route::middleware('permission:system.integration_manage')->group(function () {
            Route::post('modules', [ModuleController::class, 'store']);
            Route::put('accounts/{account}/modules/{module}', [ModuleController::class, 'toggleForAccount']);
            Route::post('roles', [RoleController::class, 'store']);
            Route::put('roles/{role}/permissions', [RoleController::class, 'syncPermissions']);
            Route::post('users/{user}/assignments', [AssignmentController::class, 'store']);
            Route::delete('assignments/{assignment}', [AssignmentController::class, 'destroy']);
        });
    });
});
