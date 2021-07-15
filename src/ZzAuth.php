<?php
declare(strict_types=1);


namespace zzAuth;

use Illuminate\Http\Request;

class ZzAuth
{

    protected Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    protected function withHeader(): Request
    {
        $ssk = $this->request->get('ssk') ?: $this->request->get('token');
        if (!empty($ssk)) {
            $this->request->headers->set('Authorization', 'Bearer ' . $ssk);
        }
        return $this->request;
    }

    public function guard($guard = null)
    {
        return auth('jwt')->setRequest($this->withHeader());
    }

    public function check(): bool
    {
        return $this->guard()->check();
    }

    public function user()
    {
        return $this->guard()->user();
    }

    public function getToken()
    {
        return $this->guard()->getToken();
    }

}
