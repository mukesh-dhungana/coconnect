<?php

namespace App\Http\Controllers\Api;

use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Services\PermissionResolver;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function __construct(private PermissionResolver $resolver) {}

    public function login(Request $request)
    {
        $data = $request->validate([
            'email'    => ['required', 'email'],
            'password' => ['required', 'string'],
        ]);

        if (! Auth::attempt($data, $request->boolean('remember'))) {
            throw ValidationException::withMessages([
                'email' => 'Those credentials do not match our records.',
            ]);
        }

        $request->session()->regenerate();

        return response()->json($this->profile($request->user()));
    }

    public function logout(Request $request)
    {
        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return response()->json(['message' => 'Signed out.']);
    }

    /** Who am I, and what may I do — the payload an SPA boots from. */
    public function me(Request $request)
    {
        return response()->json($this->profile($request->user()));
    }

    private function profile(User $user): array
    {
        $assignments = $user->roleAssignments()
            ->active()
            ->with(['role:id,name,scope_level', 'account:id,name', 'location:id,name'])
            ->get();

        return [
            'user' => [
                'id'    => $user->id,
                'name'  => $user->name,
                'email' => $user->email,
            ],
            'roles' => $assignments->map(fn ($a) => [
                'role'        => $a->role->name,
                'scope_level' => $a->scope_level,
                'account'     => $a->account?->name,
                'account_id'  => $a->account_id,
                'location'    => $a->location?->name,
                'location_id' => $a->location_id,
                'expires_at'  => $a->valid_until?->toIso8601String(),
            ])->values(),
            'permissions' => $this->resolver->permissionNames($user),
        ];
    }
}
