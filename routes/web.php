<?php

use App\Http\Controllers\DemoController;
use Illuminate\Support\Facades\Route;

Route::get('/', [DemoController::class, 'index'])->name('demo');
Route::post('/check', [DemoController::class, 'check'])->name('demo.check');
Route::post('/accounts/{account}/modules/{module}/toggle', [DemoController::class, 'toggleModule'])
    ->name('demo.toggle');
