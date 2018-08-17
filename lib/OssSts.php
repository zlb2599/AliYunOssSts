<?php

namespace Xiaohe\OssSts;

include_once 'core/aliyun-php-sdk-core/Config.php';
use Sts\Request\V20150401 as Sts;

class OssSts
{
    protected $config = [];
    
    protected $accessKeyID;
    protected $accessKeySecret;
    protected $roleArn;
    protected $tokenExpire;
    protected $policy;
    
    public function __construct($config = [])
    {
        $this->accessKeyID     = $config["AccessKeyID"];
        $this->accessKeySecret = $config["AccessKeySecret"];
        $this->roleArn         = $config["RoleArn"];
        $this->tokenExpire     = $config['TokenExpireTime'];
        $this->policy          = str_replace(
            '$BUCKET_NAME',
            $config['BucketName'],
            self::readJsonFile(
                dirname(__FILE__) . '/core/policy/' . $config['PolicyFile'] . '.txt'
            )
        );
    }
    
    public static function readJsonFile($fname)
    {
        $content = '';
        if (!file_exists($fname)) {
            throw new \Exception("The file $fname does not exist");
        }
        $handle = fopen($fname, "rb");
        while (!feof($handle)) {
            $content .= fread($handle, 10000);
        }
        fclose($handle);
        
        return $content;
    }
    
    protected function getClient()
    {
        $iClientProfile = \DefaultProfile::getProfile("cn-hangzhou", $this->accessKeyID, $this->accessKeySecret);
        $client         = new \DefaultAcsClient($iClientProfile);
        
        return $client;
    }
    
    protected function getRequest()
    {
        $request = new Sts\AssumeRoleRequest();
        $request->setRoleSessionName("client_name");
        $request->setRoleArn($this->roleArn);
        $request->setPolicy($this->policy);
        $request->setDurationSeconds($this->tokenExpire);
        
        return $request;
    }
    
    public function getToken()
    {
        $response = $this->getClient()->doAction($this->getRequest());
        $rows     = [];
        $body     = $response->getBody();
        $content  = json_decode($body);
        if ($response->getStatus() == 200) {
            $rows['StatusCode']      = 200;
            $rows['AccessKeyId']     = $content->Credentials->AccessKeyId;
            $rows['AccessKeySecret'] = $content->Credentials->AccessKeySecret;
            $rows['Expiration']      = $content->Credentials->Expiration;
            $rows['SecurityToken']   = $content->Credentials->SecurityToken;
        }
        else {
            $rows['StatusCode']   = 500;
            $rows['ErrorCode']    = $content->Code;
            $rows['ErrorMessage'] = $content->Message;
        }
        
        return $rows;
    }
}