<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class GrantRoleRequest extends FormRequest
{
    /** Route middleware already proved the permission; this validates shape. */
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'role_id'     => ['required', 'integer', 'exists:roles,id'],
            'account_id'  => ['nullable', 'integer', 'exists:accounts,id'],
            'location_id' => ['nullable', 'integer', 'exists:locations,id'],
            'valid_until' => ['nullable', 'date', 'after:now'],
            'reason'      => ['nullable', 'string', 'max:255'],
        ];
    }

    public function messages(): array
    {
        return [
            'valid_until.after' => 'A temporary grant must expire in the future.',
            'role_id.exists'    => 'That role no longer exists.',
        ];
    }
}
