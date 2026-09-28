<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateAccountRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /** Partial: only the fields sent are changed. */
    public function rules(): array
    {
        return [
            'name'     => ['sometimes', 'required', 'string', 'max:255'],
            'slug'     => ['sometimes', 'required', 'string', 'max:100', 'regex:/^[a-z0-9]+(?:-[a-z0-9]+)*$/',
                Rule::unique('accounts', 'slug')->withoutTrashed()->ignore($this->route('account'))],
            'abn'      => ['sometimes', 'nullable', 'string', 'max:20'],
            'timezone' => ['sometimes', 'nullable', 'timezone:all'],
            'locale'   => ['sometimes', 'nullable', 'string', 'max:10'],
        ];
    }

    public function messages(): array
    {
        return [
            'slug.unique' => 'Another account already uses that slug.',
            'slug.regex'  => 'A slug must be lowercase letters, digits and single hyphens.',
        ];
    }
}
