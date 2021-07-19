<?php
declare(strict_types=1);


namespace zzAuth;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\HeaderBag;

class ZzAuth
{

    /**
     * @var Request|null
     */
    protected ?Request $request;

    public function __construct(Request $request = null)
    {
        $this->request = $request;
    }

    /**
     * @param Request $request
     */
    public function setRequest(Request $request): ZzAuth
    {
        $this->request = $request;
        return $this;
    }

    protected function withHeader(): HeaderBag
    {
        $ssk = $this->request->get('ssk') ?: $this->request->get('token');
        if (!empty($ssk)) {
            $this->request->headers->set('Authorization', 'Bearer ' . $ssk);
        }
        return $this->request->headers;
    }

    public function guard($guard = null)
    {
        $this->request->headers = $this->withHeader();
        return auth('jwt')->setRequest($this->request);
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
