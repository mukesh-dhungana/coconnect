<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class AuditQueryRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'event'      => ['nullable', 'string', 'max:100'],
            'account_id' => ['nullable', 'integer'],
            // Capped so a client cannot ask for the whole ledger in one go.
            'per_page'   => ['nullable', 'integer', 'min:1', 'max:100'],
        ];
    }
}
