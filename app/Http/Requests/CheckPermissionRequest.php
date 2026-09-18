<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class CheckPermissionRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            // Not `exists:permissions,name` — asking about a permission that
            // does not exist is a fair question, and the answer is "no".
            'permission'  => ['required', 'string', 'max:100'],
            'account_id'  => ['nullable', 'integer'],
            'location_id' => ['nullable', 'integer'],
        ];
    }
}
