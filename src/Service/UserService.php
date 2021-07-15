<?php
declare(strict_types=1);

namespace zzAuth\Service;

use App\Models\User;
use Tymon\JWTAuth\Contracts\JWTSubject;
use zzAuth\Exception\BusinessException;

abstract class UserService
{
    abstract public static function insert(JWTSubject $user);

    /**
     * @param $clientId
     * @return array
     * @throws BusinessException
     * @author liaoyz 2021/7/9
     */
    public static function getUser($clientId)
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

    /**
     * @return string
     * @author liaoyz 2021/7/9
     */
    public static function refresh()
    {
        try {
            $token = auth('jwt')->refresh();
        } catch (\Exception $exception) {
            return throw new BusinessException('刷新失败');
        }
        return $token;
    }

    /**
     * @param string $userId
     */
    public static function findByUserId(string $userId)
    {
        return User::where('outsideuid', '=', $userId)->first();
    }
}
