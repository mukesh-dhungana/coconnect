<?php

namespace App\Domain\Identity\Models;

use App\Support\Tenancy\BelongsToTenant;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * A site, village or camp within one account.
 *
 * Tenant-owned: once a request has resolved its account, every Location query
 * is filtered to it automatically. Use Location::acrossTenants() where that is
 * genuinely wrong — the scope picker on an admin screen, for instance.
 */
class Location extends Model
{
    use BelongsToTenant, SoftDeletes;

    protected $fillable = ['account_id', 'name', 'slug', 'suburb', 'state'];

    public function account()
    {
        return $this->belongsTo(Account::class);
    }
}
