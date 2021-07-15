<?php
declare(strict_types=1);

namespace zzAuth\Service;

use App\Models\User;
use Tymon\JWTAuth\Contracts\JWTSubject;
use zzAuth\Exception\BusinessException;

abstract class UserService
{
    abstract public function insert(JWTSubject $user);

    public function getUser($clientId)
    {
        try {
            $user = auth('jwt')->user();
        } catch (\Exception $e) {
            throw new BusinessException('Token验证失败');
        }
        if (!hash_equals(auth('jwt')->getClaim('client'), $clientId)) {
            throw new BusinessException('Token验证失败');
        }
//        $model = UserService::findByUserId((string)$auth['id']);
//        if (empty($model)) throw new BusinessException('获取用户信息失败');
        if ($user['status'] == 0) throw new BusinessException('用户已被禁用');
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
            $token = auth('jwt')->refresh();
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
