# Spike: can Laravel Permission (teams on `account_id`) carry location and module scope?

**Date:** 2026-09-23 · **Owner:** Mukesh Dhungana · **Status:** Done

## Answer

**Yes, go ahead with the permission schema build.** `spatie/laravel-permission` v8, with
teams keyed on `account_id`, carries both extra scopes. The one condition: Spatie decides
*what a role grants* and the app decides *where it applies*. The spike found three gaps.
All three are now fixed with regression tests, and none of them needed a schema change.

Permission checks use **Spatie's own API**: `$user->can()`, `@can`, `hasPermissionTo()`
and Spatie's `permission:` middleware. They're scope-correct because `User` overrides two
Spatie methods (see *Model*).

## Model

| Scope | Carried by | Enforced by |
| --- | --- | --- |
| Account | Spatie team key: `roles.account_id` (null = system role) and `user_role_assignments.account_id` | Spatie `HasRoles::roles()` (filters pivot and role to the active team) |
| Location | `user_role_assignments.location_id` (null = whole account). Spatie ignores it | `User::roles()` override (also drops revoked and expired grants) |
| Module | `permissions.module_id` + `account_module.is_enabled` | `User::hasPermissionTo()` override, checked **before** `is_admin` |
| Global | `users.is_admin` (Spatie can't express "every team") | `User::hasPermissionTo()` override |

The `tenant` middleware sets the scope once per request: Spatie's team (the account) plus
the location, via `PermissionScope`. To ask about a different scope, use
`$user->hasPermission($perm, $accountId, $locationId)`. It restores the request's scope
afterwards.

Spatie's own primary key on `model_has_roles` is replaced by a surrogate id plus a MySQL
unique index on `(model, role, account, COALESCE(location,0), active)`. That index allows
the same role at two locations and keeps revoked rows for audit. A `CHECK` constraint ties
`scope_level` to whether `location_id` is set.

## Checklist results

All 53 backend tests pass on MySQL (`php artisan test`).

| Step | Result | Evidence (`tests/Feature/RbacTest.php`) |
| --- | --- | --- |
| Module scope | ✅ | Module disabled → deny everything, including super admin; unknown permission → deny |
| Account scoping with teams enabled | ✅ | Account role confined to its account and covers every location in it; permissions from several roles combine |
| Location layered on top | ✅ | Location role confined to its location; can't answer account-wide questions; same role at two locations; expiry, revoke and re-grant |

## Gaps found (all fixed)

Each gap was shown with a probe test, and the probes are now regression tests in
`tests/Feature/RbacTest.php`. All 53 tests pass.

### 1. Spatie's own Gate hook bypasses location, revocation and module scope — High (latent)

`register_permission_check_method => true` makes Spatie register a `Gate::before`.
Package providers boot before `AppServiceProvider`, so **Spatie's hook runs first**. It
checks only "has a role in the active team", and it returns `true` as soon as it matches.

With the team context set (`setPermissionsTeamId($accountId)`), `$user->can('roster.publish', …)`
returned `true` in each of these cases:

- at a location the user has no grant for
- after the grant was revoked
- with the module disabled for the account

Today this is latent: the team is only set inside `PermissionResolver::withTeam()` and is
restored afterwards. But setting the team in middleware is the pattern Spatie's docs
recommend, and the first person to add it opens all three holes.

**Fixed:** the hook stays on (`register_permission_check_method => true`), but now it
gives correct answers. Spatie's hook calls `hasPermissionTo()` and reads `roles()`, and
`User` overrides both, so the location, revocation, expiry and module rules apply to
Spatie's own check. The app's separate `Gate::before` and `EnsurePermission` middleware
are gone, and routes use Spatie's `PermissionMiddleware`.

Regression tests cover `can()`, `hasPermissionTo()` and the `permission:` middleware, and
also check that a `roles` relation Spatie has already loaded on the model isn't reused
after a revoke or an expiry. Disabling either override, or the relation reset, fails
8–13 tests.

### 2. A location role can be granted with another account's location — High

`GrantRole` checks that a location is present, not that it belongs to the account. A grant
at account A with a location from account B was accepted, and
`hasPermission(…, A, locationOfB)` returned `true`. The `POST /users/{user}/assignments`
endpoint can reach this.

**Fixed:** `GrantRole::assertLocationInAccount()` rejects it with a 422 on `location_id`.
Not done: backing it with a composite foreign key `(location_id, account_id) → locations(id, account_id)`.

### 3. A role owned by another account can be granted — Medium

This was accepted and audited as `role.granted`, but it never grants anything, because
Spatie's `roles()` filters it out. The admin UI shows access that doesn't exist.

**Fixed:** `GrantRole::assertRoleAvailable()` rejects it with a 422 on `role_id`.

## Constraints to keep

- Spatie's **reads** are safe to use. Its **writes** are not: `assignRole`, `removeRole` and
  `syncRoles` can't store a location or keep revoked rows, and a guard test bans them.
  Grants go through `GrantRole` / `RevokeRole`.
- Keep both `User` overrides (`roles()`, `hasPermissionTo()`). With the hook on, removing
  either one lets Spatie grant too much.
- `hasRole()` uses the scope-filtered `roles()`, but Spatie caches the loaded relation on
  the model. For permission decisions, use `can()` / `hasPermissionTo()`, which reload
  the relation on every call.
- Spatie's team id is static state. The `tenant` middleware resets it on every request;
  `hasPermission()` / `PermissionScope::within()` restore it afterwards. Enable
  `register_octane_reset_listener` if Octane is ever adopted.
- After writing `permission_role` directly (`sync`, `attach`), call
  `forgetCachedPermissions()`. The role repository and the seeder both do.
- The unique-grant index and scope `CHECK` exist only on MySQL. Tests must keep running on
  MySQL (as `phpunit.xml` does), not SQLite.

## Open question for product (with product, pending)

Module enablement is per **account**. If a client may license a module for some sites
only, that needs a `location_module` table and a check in the resolver. Better to decide
now than after the build.

## Next steps

1. ~~Apply fixes 1–3 with regression tests.~~ Done.
2. Get product's answer on per-location module licensing.
3. Close this spike and unblock the permission schema build.
