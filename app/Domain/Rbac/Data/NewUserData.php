<?php

namespace App\Domain\Rbac\Data;

final readonly class NewUserData
{
    public function __construct(
        public string $firstName,
        public string $lastName,
        public string $email,
        public ?string $mobile = null,
        public ?int $accountId = null,
    ) {}

    public static function fromArray(array $input): self
    {
        return new self(
            firstName: $input['first_name'],
            lastName: $input['last_name'],
            email: $input['email'],
            // validate() omits absent optional keys entirely, so coalesce.
            mobile: $input['mobile'] ?? null,
            accountId: $input['account_id'] ?? null,
        );
    }

    public function fullName(): string
    {
        return trim("{$this->firstName} {$this->lastName}");
    }
}
