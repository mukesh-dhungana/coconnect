<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StoreRoleRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'account_id' => ['nullable', 'integer', 'exists:accounts,id'],
            'key' => ['required', 'string', 'max:100', 'regex:/^[a-z][a-z0-9_]*$/',
                // Unique per account, not globally: two clients
                // may each define a role called "supervisor".
                Rule::unique('roles', 'key')
                    ->where(fn ($q) => $q->where('account_id', $this->input('account_id')))],
            'name' => ['required', 'string', 'max:255'],
            'description' => ['nullable', 'string', 'max:255'],
            // No 'global': that scope level is users.is_admin, not a role.
            'scope_level' => ['required', Rule::in(['account', 'location'])],
        ];
    }

    public function messages(): array
    {
        return [
            'key.unique' => 'A role with that key already exists in this scope.',
            'key.regex' => 'A role key must be lowercase letters, digits and underscores.',
        ];
    }
}
