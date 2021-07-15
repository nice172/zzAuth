<?php
declare(strict_types=1);

namespace zzAuth\Lib;

use RuntimeException;

class SignatureUtil
{

    protected array $values = array();

    /**
     * 设置签名，详见签名生成算法类型
     * @param string $value
     **/
    public function setSignType($sign_type)
    {
        $this->values['sign_type'] = $sign_type;
        return $sign_type;
    }

    /**
     * 设置签名，详见签名生成算法
     * @param string $value
     **/
    public function setSign($config)
    {
        $sign = $this->makeSign($config);
        $this->values['sign'] = $sign;
        return $sign;
    }

    /**
     * 获取签名，详见签名生成算法的值
     * @return string
     **/
    public function getSign()
    {
        return $this->values['sign'];
    }

    /**
     * 判断签名，详见签名生成算法是否存在
     * @return true 或 false
     **/
    public function isSignSet()
    {
        return array_key_exists('sign', $this->values);
    }

    /**
     * 获取设置的值
     */
    public function getValues()
    {
        return $this->values;
    }

    /**
     *
     * 产生随机字符串，不长于32位
     * @param int $length
     * @return string
     */
    public function getNonceStr($length = 32): string
    {
        $chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        $str = '';
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }

    /**
     * 开放平台分配的appid
     * @param string $value
     **/
    public function setAppid($value)
    {
        $this->values['appId'] = $value;
    }

    /**
     * 开放平台分配的appSecret
     * @return string
     **/
    public function getAppid()
    {
        return $this->values['appId'];
    }

    /**
     * 设置支付时间戳
     * @param string $value
     **/
    public function setTimeStamp($value)
    {
        $this->values['timeStamp'] = $value;
    }

    /**
     * 获取支付时间戳的值
     * @return string
     **/
    public function getTimeStamp()
    {
        return $this->values['timeStamp'];
    }

    /**
     * 随机字符串
     * @param string $value
     **/
    public function setNonceStr($value)
    {
        $this->values['nonceStr'] = $value;
    }

    /**
     * 设置扩展字符串
     * @param string $value
     **/
    public function setPackage($value)
    {
        $this->values['package'] = $value;
    }

    /**
     * 获取扩展字符串的值
     * @return string
     **/
    public function getPackage()
    {
        return $this->values['package'];
    }

    /**
     * @param array $values
     */
    public function setValues(array $values)
    {
        $this->values = $values;
    }

    /**
     * 格式化参数格式化成url参数
     * @param array $values
     * @return string
     * @author liaoyz 2021-01-30 16:34
     */
    public function toUrlParams(array $values = []): string
    {
        $values = !empty($values) ? $values : $this->values;
        ksort($values);
        $string = "";
        foreach ($values as $key => $value) {
            if ($key != "sign" && $value != "" && !is_array($value)) {
                $string .= $key . "=" . $value . "&";
            }
        }
        $string = trim($string, "&");
        return $string;
    }

    /**
     * 生成签名 签名，本函数不覆盖sign成员变量，如要设置签名需要调用SetSign方法赋值
     * @param OpenApiConfig $config 配置对象
     * @param bool $needSignType 是否需要补signtype
     * @return string
     * @throws RuntimeException
     * @author liaoyz
     */
    public function makeSign(OpenApiConfig $config, $needSignType = true): string
    {
        if (!array_key_exists('appId', $this->values) || empty($this->getAppid())) {
            $this->setAppid($config->getAppId());
        }
        if (empty($this->getAppid())) {
            throw new RuntimeException('签名参数错误');
        }
        if ($needSignType) {
            $this->setSignType($config->getSignType());
        }
        //签名步骤一：按字典序排序并‘&’拼接参数
        //ksort($this->values);
        $string = $this->toUrlParams();
        //签名步骤二：在string后加入KEY
        $string = $string . "&key=" . $config->getAppSecret();
//        echo $string;exit;
//        file_put_contents(storage_path().'/sign.txt',$string);
        //签名步骤三：MD5加密或者HMAC-SHA256
        if ($config->getSignType() == "MD5") {
            $string = md5($string);
        } else if ($config->getSignType() == "HMAC-SHA256") {
            $string = hash_hmac("sha256", $string, $config->getAppSecret());
        } else {
            throw new RuntimeException("签名类型不支持！");
        }

        //签名步骤四：所有字符转为大写
        return strtoupper($string);
    }

}
