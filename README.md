# Co Connect — RBAC backend

Laravel 13 implementation of the access-control module: dynamic modules,
roles, permissions and multi-role users, scoped at global / account / location.

Designed against the real `Co Connect App` database, not a greenfield schema.

## Run it

```bash
composer install
cp .env.example .env && php artisan key:generate

# point .env at your MySQL, then:
php artisan migrate:fresh --seed
php artisan serve
```

Open <http://127.0.0.1:8000>. The demo page is the whole module on one screen:
modules with per-account toggles, every user and the roles they hold, and a
live permission checker.

## The model

| Table | Purpose |
| --- | --- |
| `modules` | A module is a **row**. Add one at runtime, no deploy. |
| `account_module` | Per-tenant enablement — the commercial boundary. |
| `permissions` | Belongs to a module. `is_high_risk` flags dangerous ones. |
| `roles` | `account_id` null = system role; set = that client's own role. |
| `permission_role` | Which permissions a role carries. |
| `user_role_assignments` | A user may hold **many** roles, at different scopes. |

### Three rules

1. **Deny by default.** A permission is granted only if an active assignment
   carries it, its scope covers the target, and the module is enabled for that
   account.
2. **Module enablement is enforced in the permission check**
   (`User::hasPermissionTo`), not just hidden in the UI. A disabled module
   denies even a System Administrator.
3. **Grants are revoked, never deleted.** `revoked_at` keeps the history, and
   the generated `active_guard` column drops revoked rows out of the unique
   index so a role can be granted again later.

## Demo script

Five things worth showing a client, in order:

1. **Disable Travel for City of Rio** on the demo page. The Travel Coordinator
   immediately loses `travel.book` *for that account only* — the same person
   keeps it at Snazzy Resources.
2. **Check `emergency.incident_activate` for Petr at Site** → ALLOWED.
   Same check at Village → DENIED. Location scoping, live.
3. **Look at Petr's roles.** He holds two at once: ERT Member permanently, and
   a temporary EMT Leader elevation with a visible countdown.
4. **Create a module over the API** (`POST /api/v1/modules`) and watch it appear
   in the catalogue without a deploy.
5. **Try to break it** — grant the same role twice, or grant a location role
   without a location. Both are refused with a readable message, and the
   database constraint stands behind the validation.

## API

```
GET    /api/v1/modules                              catalogue
POST   /api/v1/modules                              create at runtime
GET    /api/v1/accounts/{account}/modules           enablement per account
PUT    /api/v1/accounts/{account}/modules/{module}  toggle

GET    /api/v1/roles                                system + account roles
POST   /api/v1/roles                                define a role
PUT    /api/v1/roles/{role}/permissions             replace its permission set

GET    /api/v1/users/{user}/assignments             roles held + effective perms
POST   /api/v1/users/{user}/assignments             grant
DELETE /api/v1/assignments/{assignment}             revoke

GET    /api/v1/users/{user}/check?permission=&account_id=&location_id=
```

The demo routes are unauthenticated so they can be exercised directly. In
production they sit behind `auth:sanctum` plus a `system.*` permission check.

## Tests

```bash
php artisan test
```

12 Pest tests cover scope widening, module enablement, multi-role union,
temporary expiry, duplicate rejection, scope validation and revoke/re-grant.

## Code layout

Organised by **domain module**, not by technical layer. Each module owns its
models, actions and services in one directory.

```
app/Domain/
  Rbac/            ◀ built — this module
    Models/        Module, Permission, Role, UserRoleAssignment
    Actions/       GrantRole, RevokeRole
    Services/      PermissionCatalog    ← module enablement + "anywhere" lists
    Support/       PermissionScope      ← account (Spatie team) + location in scope
    Policies/      (record-level rules land here)
  Identity/        ◀ built — the tables RBAC attaches to
    Models/        User, Account, Location

  People/          ◁ planned        Accommodation/   ◁ planned
  Roster/          ◁ planned        Cleaning/        ◁ planned
  Travel/          ◁ planned        Emergency/       ◁ planned
  Compliance/      ◁ planned        Messaging/       ◁ planned
```

Every module gets the same four folders:

| Folder | Holds | Rule |
| --- | --- | --- |
| `Models/` | Tables this module owns | No other module writes to them |
| `Actions/` | One class per state change | Transaction + policy + audit inside |
| `Services/` | Query and calculation | Read-side; no writes |
| `Policies/` | Record-level authorisation | Called by actions, not controllers |

Controllers live outside the domain in `app/Http/Controllers/` and stay thin:
validate, call one action, serialise. An action can also be called by a job,
a scheduler or a seeder — a controller cannot.

Other modules never read the RBAC tables. They use spatie/laravel-permission's
own API, which answers for the account and location the `tenant` middleware put
in scope:

```php
$user->can('roster.publish');                       // or @can, or hasPermissionTo()
Route::middleware('permission:roster.publish');     // Spatie's middleware

// A different scope than the request's:
$user->hasPermission('roster.publish', $accountId, $locationId);
```

`User::roles()` and `User::hasPermissionTo()` override Spatie's to add location,
revocation, expiry, module enablement and the super-admin flag -- that is what
makes the package's API safe here. Never call `assignRole` / `removeRole` /
`syncRoles`; grants go through `GrantRole` / `RevokeRole`.

## Key files

| Path | What |
| --- | --- |
| `app/Domain/Identity/Models/User.php` | `roles()` / `hasPermissionTo()` overrides -- the scope rules on Spatie's check. |
| `app/Domain/Rbac/Support/PermissionScope.php` | Account + location every check answers for. |
| `app/Domain/Rbac/Services/PermissionCatalog.php` | Module enablement; cross-account permission and module lists. |
| `app/Domain/Rbac/Actions/GrantRole.php` | Validates scope and duplicates before writing. |
| `app/Domain/Rbac/Actions/RevokeRole.php` | Revokes without deleting. |
| `database/migrations/*_create_rbac_tables.php` | Schema, constraints, generated columns. |
| `database/seeders/RbacSeeder.php` | 7 modules, 26 permissions, 11 roles, demo tenants. |
| `resources/views/demo.blade.php` | The client-facing demo page. |
