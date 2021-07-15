<?php
declare(strict_types=1);


namespace zzAuth;

use Illuminate\Support\Facades\Cache;
use Psr\SimpleCache\InvalidArgumentException;
use Tymon\JWTAuth\Facades\JWTAuth;
use zzAuth\Exception\BusinessException;
use zzAuth\Exception\ValidateException;
use zzAuth\Lib\OpenApiConfig;
use zzAuth\Lib\SignatureUtil;

class ZzRedirect
{
    /**
     * @return string|null
     * @throws BusinessException
     * @throws InvalidArgumentException
     */
    private function getAccessToken(): ?string
    {
        $accessToken = Cache::get('accessToken');
        if (empty($accessToken)) {
            $response = $this->httpRequest('/api/gateway/getAccessToken', $this->requestParams());
            if (empty($response) || $response['code'] != 200) {
                throw new BusinessException(isset($response['message']) ? $response['message'] : '获取accessToken失败');
            }
            $accessToken = $response['data']['accessToken'];
            Cache::set('accessToken', $accessToken, 3600);
        }
        return $accessToken;
    }

    private function buildHeader($accessToken): array
    {
        return [
            'Accept: application/json',
            'Authorization: Bearer ' . $accessToken,
            'X-Requested-With: XMLHttpRequest',
            'ApiVersion: v1'
        ];
    }

    /**
     * @param string $ticket
     * @param \Closure $closure
     * @param array|null $claims
     * @return mixed
     * @throws BusinessException
     * @throws InvalidArgumentException
     * @throws ValidateException
     */
    public function forward(string $ticket, \Closure $closure, ?array $claims)
    {
        if (empty($ticket)) throw new ValidateException('ticket不能为空');
        try {
            $accessToken = $this->getAccessToken();
        } catch (\Exception $e) {
            throw $e;
        }
        $params = $this->requestParams([
            'ticket' => $ticket
        ]);
        $header = $this->buildHeader($accessToken);
        $response = $this->httpRequest('/api/user/getBasicInfo', $params, $header);
        if (!empty($response) && $response['code'] == 200) {
            $user = $response['data'];
            $params = $this->requestParams([
                'userID' => $user['userID']
            ]);
            $response = $this->httpRequest('/api/user/getUserInfo', $params, $header);
            if (!empty($response) && $response['code'] == 200) {
                $token = JWTAuth::customClaims($claims)->fromSubject(call_user_func($closure, array_merge($user, $response['data'])));
                header('Location:' . config('zzconfig.redirect_url') . '/index?ssk=' . $token);
                exit;
            }
        }
        throw new BusinessException(isset($response['message']) ? $response['message'] : '获取用户信息失败');
    }

    private function requestParams($params = []): array
    {
        $appid = config('zzconfig.appId');
        $appsecret = config('zzconfig.appSecret');
        $timestamp = time();
        $config = new OpenApiConfig();
        $config->setAppId($appid);
        $config->setAppSecret($appsecret);
        $signUtil = new SignatureUtil();
        $nonceStr = $signUtil->getNonceStr();
        $signUtil->setNonceStr($nonceStr);
        $signUtil->setTimeStamp($timestamp);
        if (!empty($params)) {
            $signUtil->setPackage($signUtil->toUrlParams($params));
        }
        $makeSign = $signUtil->makeSign($config);
        $data = [
            'appid' => $appid,
            'timestamp' => $timestamp,
            'nonceStr' => $nonceStr,
            'sign' => $makeSign,
        ];
        return array_merge($data, $params);
    }

    private function httpRequest($url, $data = [], $header = [], $method = null)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, config('zzconfig.app_api') . $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        if (!empty($data)) {
            $jsonData = json_encode($data);
            $header[] = 'Content-Type: application/json';
            $header[] = 'Content-Length: ' . strlen($jsonData);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonData);
        }
        if (!empty($header)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
        }
        $res = curl_exec($ch);
        curl_close($ch);
        return @json_decode($res, true);
    }
}
