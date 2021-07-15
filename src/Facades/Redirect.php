<?php
declare(strict_types=1);


namespace zzAuth\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * Class Redirect
 * @package zzAuth\Facades
 * @author liaoyz 2021/7/15
 */
class Redirect extends Facade
{

    protected static function getFacadeAccessor()
    {
        return 'redirect';
    }

}
