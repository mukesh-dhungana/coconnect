<?php

namespace App\Http\Controllers\Api;

use App\Domain\Identity\Models\User;
use App\Domain\Rbac\Services\PermissionResolver;
use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Support\Concerns\RespondsWithJson;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    use RespondsWithJson;

    public function __construct(private PermissionResolver $resolver) {}

    public function login(LoginRequest $request): JsonResponse
    {
        if (! Auth::attempt($request->credentials(), $request->boolean('remember'))) {
            throw ValidationException::withMessages([
                'email' => 'Those credentials do not match our records.',
            ]);
        }

        $request->session()->regenerate();

        return $this->ok($this->profile($request->user()));
    }

    public function logout(Request $request): JsonResponse
    {
        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return $this->ok(['message' => 'Signed out.']);
    }

    /** Who am I, and what may I do — the payload an SPA boots from. */
    public function me(Request $request): JsonResponse
    {
        return $this->ok($this->profile($request->user()));
    }

    private function profile(User $user): array
    {
        $assignments = $user->roleAssignments()
            ->active()
            ->with(['role:id,name,scope_level', 'account:id,name', 'location:id,name'])
            ->get();

        return [
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                // The global scope level. A super admin holds no assignments,
                // so without this the SPA cannot tell them from a user with
                // nothing granted at all.
                'is_admin' => (bool) $user->is_admin,
            ],
            'roles' => $assignments->map(fn ($a) => [
                'role' => $a->role->name,
                'scope_level' => $a->scope_level,
                'account' => $a->account?->name,
                'account_id' => $a->account_id,
                'location' => $a->location?->name,
                'location_id' => $a->location_id,
                'expires_at' => $a->valid_until?->toIso8601String(),
            ])->values(),
            'permissions' => $this->resolver->permissionNames($user),
        ];
    }
}
