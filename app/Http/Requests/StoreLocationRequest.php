<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class StoreLocationRequest extends FormRequest
{
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
        $account = $this->route('account');

        return [
            'name'   => ['required', 'string', 'max:255'],
            // Unique per account, not globally: two clients may each have a
            // location called "village".
            'slug'   => ['required', 'string', 'max:100', 'regex:/^[a-z0-9]+(?:-[a-z0-9]+)*$/',
                Rule::unique('locations', 'slug')->withoutTrashed()->where('account_id', $account->id)],
            'suburb' => ['nullable', 'string', 'max:100'],
            'state'  => ['nullable', 'string', 'max:50'],
        ];
    }

    public function messages(): array
    {
        return [
            'slug.unique' => 'This account already has a location with that slug.',
            'slug.regex'  => 'A slug must be lowercase letters, digits and single hyphens.',
        ];
    }
}
