<?php
declare(strict_types=1);

namespace zzAuth\Lib;

class OpenApiConfig
{
    /**
     * 开放平台分配的appid
     * @var $appId
     */
    private $appId;

    /**
     * 开放平台分配的appSecret
     * @var $appSecret
     */
    private $appSecret;

    /**
     * @return mixed
     */
    public function getAppId()
    {
        return $this->appId;
    }

    /**
     * @param mixed $appId
     */
    public function setAppId($appId): void
    {
        $this->appId = $appId;
    }

    /**
     * @return mixed
     */
    public function getAppSecret()
    {
        return $this->appSecret;
    }

    /**
     * @param mixed $appSecret
     */
    public function setAppSecret($appSecret): void
    {
        $this->appSecret = $appSecret;
    }

    public function getSignType()
    {
        return "HMAC-SHA256";
    }

    public function getSSLCertPath(&$sslCertPath, &$sslKeyPath)
    {
//        $sslCertPath = '../cert/apiclient_cert.pem';
//        $sslKeyPath = '../cert/apiclient_key.pem';
    }
}
