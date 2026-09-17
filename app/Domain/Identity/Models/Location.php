<?php

namespace App\Domain\Identity\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Location extends Model
{
    use SoftDeletes;

    protected $fillable = ['account_id', 'name', 'slug', 'suburb', 'state'];

    public function account() { return $this->belongsTo(Account::class); }
}
