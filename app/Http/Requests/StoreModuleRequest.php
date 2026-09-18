<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StoreModuleRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            // Lowercase snake: the key appears in permission names and in code.
            'key'         => ['required', 'string', 'max:50', 'regex:/^[a-z][a-z0-9_]*$/',
                              Rule::unique('modules', 'key')],
            'name'        => ['required', 'string', 'max:100'],
            'description' => ['nullable', 'string', 'max:255'],
            'icon'        => ['nullable', 'string', 'max:50'],
            'sort_order'  => ['nullable', 'integer', 'min:0', 'max:9999'],
        ];
    }

    public function messages(): array
    {
        return [
            'key.regex' => 'A module key must be lowercase letters, digits and underscores, starting with a letter.',
        ];
    }
}
