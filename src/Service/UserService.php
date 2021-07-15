<?php
declare(strict_types=1);

namespace zzAuth\Service;

use App\Models\User;
use Tymon\JWTAuth\Contracts\JWTSubject;
use zzAuth\Exception\BusinessException;
use zzAuth\Exception\ValidateException;
use zzAuth\ZzAuth;

abstract class UserService
{

    protected ZzAuth $auth;

    public function __construct(ZzAuth $auth)
    {
        $this->auth = $auth;
    }

    abstract public function insert(JWTSubject $user);

    public function getUser($clientId)
    {
        try {
            $this->auth->guard()->invalidate();
            $user = $this->auth->guard()->user();
            if (empty($user)) throw new BusinessException('获取用户信息失败');
            if ($user['status'] == 0) throw new BusinessException('用户已被禁用');
            if (!hash_equals($this->auth->guard()->getClaim('client'), $clientId)) {
                throw new ValidateException('客户端异常');
            }
        } catch (\Exception $e) {
            throw new ValidateException($e->getMessage());
        }
        return [
            'username' => $user['name'],
            'usertype' => $user['type'],
            'avator' => $user['img'],
            'position' => []
        ];
    }

    public function refresh()
    {
        try {
            $token = $this->auth->guard()->refresh();
        } catch (\Exception $exception) {
            throw new BusinessException('刷新失败');
        }
        return $token;
    }

    public function findByUserId(string $userId)
    {
        return User::where('outsideuid', '=', $userId)->first();
    }
}
