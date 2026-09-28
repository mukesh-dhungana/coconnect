<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class StoreAccountRequest extends FormRequest
{
    /** Route middleware already proved the permission; this validates shape. */
    public function authorize(): bool
    {
        return true;
    }

    /** The slug is optional on create: it follows the name unless given. */
    protected function prepareForValidation(): void
    {
        if (! $this->filled('slug') && $this->filled('name')) {
            $this->merge(['slug' => Str::slug($this->input('name'))]);
        }
    }

    public function rules(): array
    {
        return [
            'name'     => ['required', 'string', 'max:255'],
            'slug'     => ['required', 'string', 'max:100', 'regex:/^[a-z0-9]+(?:-[a-z0-9]+)*$/',
                Rule::unique('accounts', 'slug')->withoutTrashed()],
            'abn'      => ['nullable', 'string', 'max:20'],
            'timezone' => ['nullable', 'timezone:all'],
            'locale'   => ['nullable', 'string', 'max:10'],
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
