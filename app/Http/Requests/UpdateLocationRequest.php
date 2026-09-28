<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateLocationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Partial: only the fields sent are changed. account_id is deliberately
     * absent -- moving a location to another account would silently carry
     * its grants into another tenant.
     */
    public function rules(): array
    {
        $account = $this->route('account');

        return [
            'name'   => ['sometimes', 'required', 'string', 'max:255'],
            'slug'   => ['sometimes', 'required', 'string', 'max:100', 'regex:/^[a-z0-9]+(?:-[a-z0-9]+)*$/',
                Rule::unique('locations', 'slug')->withoutTrashed()
                    ->where('account_id', $account->id)->ignore($this->route('location'))],
            'suburb' => ['sometimes', 'nullable', 'string', 'max:100'],
            'state'  => ['sometimes', 'nullable', 'string', 'max:50'],
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
