<?php

use App\Http\Controllers\Api\AssignmentController;
use App\Http\Controllers\Api\ModuleController;
use App\Http\Controllers\Api\RoleController;
use Illuminate\Support\Facades\Route;

/*
| RBAC API — /api/v1
|
| Auth is omitted in the demo so the endpoints can be exercised directly.
| In production these sit behind auth:sanctum plus a `system.*` permission
| check; the resolver is already the authority for that.
*/

Route::prefix('v1')->group(function () {
    // Modules — dynamic catalogue and per-account enablement
    Route::get('modules', [ModuleController::class, 'index']);
    Route::post('modules', [ModuleController::class, 'store']);
    Route::get('accounts/{account}/modules', [ModuleController::class, 'forAccount']);
    Route::put('accounts/{account}/modules/{module}', [ModuleController::class, 'toggleForAccount']);

    // Roles and their permission sets
    Route::get('roles', [RoleController::class, 'index']);
    Route::post('roles', [RoleController::class, 'store']);
    Route::put('roles/{role}/permissions', [RoleController::class, 'syncPermissions']);

    // Assignments — a user may hold many roles
    Route::get('users/{user}/assignments', [AssignmentController::class, 'index']);
    Route::post('users/{user}/assignments', [AssignmentController::class, 'store']);
    Route::delete('assignments/{assignment}', [AssignmentController::class, 'destroy']);

    // The check itself
    Route::get('users/{user}/check', [AssignmentController::class, 'check']);
});
