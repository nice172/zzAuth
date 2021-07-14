<?php
declare(strict_types=1);

namespace zzAuth\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * Class Auth
 * @author liaoyz 2021/7/14
 */
class ZzAuth extends Facade
{

    protected static function getFacadeAccessor(): string
    {
        return 'zzAuth';
    }

}
