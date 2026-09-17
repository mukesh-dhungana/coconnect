<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Legacy role-code mapping
    |--------------------------------------------------------------------------
    |
    | The existing application stores roles as string codes on two pivots:
    |
    |   account_user.role   '10' | '20' | '30' | '40'
    |   location_user.role  '120' | '130'
    |
    | THESE MAPPINGS ARE NOT YET CONFIRMED. The distribution of values suggests
    | a reading, but nothing in the database documents it, and a wrong mapping
    | silently grants or removes access. The backfill command therefore refuses
    | to commit while any code below is null.
    |
    | Set each code to a role `key` from the roles table, then run:
    |
    |   php artisan rbac:backfill --dry-run    (always safe, writes nothing)
    |   php artisan rbac:backfill --commit
    |
    */

    'legacy_map' => [

        // account_user.role  →  an account-scoped role key
        'account' => [
            '10' => null,   // 22 rows — suspected: standard member
            '20' => null,   //  1 row  — suspected: elevated
            '30' => null,   // 19 rows — suspected: manager
            '40' => null,   //  1 row  — suspected: administrator
        ],

        // location_user.role  →  a location-scoped role key
        'location' => [
            '120' => null,  // 95 rows — suspected: standard site access
            '130' => null,  //  2 rows — suspected: site manager
        ],
    ],

    /*
    | Written to user_role_assignments.grant_reason so migrated grants stay
    | distinguishable from ones an administrator made deliberately.
    */
    'backfill_reason' => 'migrated_from_legacy',
];
