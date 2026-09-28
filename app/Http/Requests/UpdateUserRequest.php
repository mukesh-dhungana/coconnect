<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateUserRequest extends FormRequest
{
    /** Route middleware proved the permission; the controller proves the person. */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Partial: only the fields sent are changed. Profile only -- is_admin,
     * the password and account membership are not editable here.
     */
    public function rules(): array
    {
        $user = $this->route('user');

        return [
            'first_name' => ['sometimes', 'required', 'string', 'max:100'],
            'last_name'  => ['sometimes', 'required', 'string', 'max:100'],
            'email'      => ['sometimes', 'required', 'email', 'max:190', Rule::unique('users', 'email')->ignore($user)],
            'mobile'     => ['sometimes', 'nullable', 'string', 'max:20', Rule::unique('users', 'mobile')->ignore($user)],
        ];
    }

    public function messages(): array
    {
        return [
            'email.unique'  => 'Somebody already uses that email address.',
            'mobile.unique' => 'Somebody already uses that mobile number.',
        ];
    }
}
