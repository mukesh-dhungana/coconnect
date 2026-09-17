<?php

namespace App\Domain\Rbac\Support;

use Illuminate\Database\Eloquent\Model;
use Spatie\Activitylog\Models\Activity;

/**
 * Every change to who can do what is a security event and is recorded.
 *
 * Grants, revocations, module toggles and role permission changes all land
 * in one log with the actor, the subject and enough properties to answer
 * "who gave this person access, when, and why" without reading code.
 */
class RbacAudit
{
    public const LOG = 'rbac';

    public static function record(string $event, Model $subject, array $properties = []): void
    {
        activity(self::LOG)
            ->performedOn($subject)
            ->causedBy(auth()->user())
            ->withProperties($properties)
            ->event($event)
            ->log($event);
    }

    /** @return \Illuminate\Database\Eloquent\Builder<Activity> */
    public static function query()
    {
        return Activity::inLog(self::LOG)->latest();
    }
}
