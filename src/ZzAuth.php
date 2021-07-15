<?php
declare(strict_types=1);


namespace zzAuth;

/**
 * Class Auth
 * @package zzAuth
 * @author liaoyz 2021/7/14
 */
class ZzAuth
{

    public function guard($guard = null){
        return auth('jwt');
    }

    public function check(): bool
    {
        return $this->guard()->check();
    }

    public function user(){
        return $this->guard()->user();
    }

    public function getToken(){
        return $this->guard()->getToken();
    }

}
