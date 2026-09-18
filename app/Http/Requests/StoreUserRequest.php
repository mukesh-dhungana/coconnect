<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StoreUserRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'first_name' => ['required', 'string', 'max:100'],
            'last_name'  => ['required', 'string', 'max:100'],
            'email'      => ['required', 'email', 'max:190', Rule::unique('users', 'email')],
            'mobile'     => ['nullable', 'string', 'max:20', Rule::unique('users', 'mobile')],
            'account_id' => ['nullable', 'integer', 'exists:accounts,id'],
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
