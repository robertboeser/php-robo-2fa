<?php
namespace Robo\Robo2fa;

class YubiKey {
    protected $clientId;
    protected $secretKey;

    function __construct($client, $secret) {
        $this->clientId = $client;
        $this->secretKey = $secret;
    }

    function verify($token) {
        $nonce = static::generateNonce();

        $params = [
            'id' => $this->clientId,
            'otp' => $token,
            'nonce' => $nonce,
        ];
        $h = $this->calculateHash($params);
        $params['h'] = urlencode($h);
        $query = http_build_query($params);

        $url = "https://api.yubico.com/wsapi/2.0/verify?$query";
        $response = file_get_contents($url);
        $response = $this->parseResponse($response);

        if($token !== $response['otp']) return false;
        if($nonce !== $response['nonce']) return false;
        if($response['status'] !== 'OK') return false;

        $h = str_replace(' ', '+', $response['h']);
        unset($response['h']);

        $hash = $this->calculateHash($response);
        return $hash === $h;
    }

    function getIdFromToken($token) {
        return substr($token, 0, 12);
    }

    function parseResponse($string) {
        $parsed = [];
        $string = str_replace(["\n", "\r"], ['&', ''], $string);
        parse_str($string, $parsed);
        return $parsed;
    }

    function calculateHash($params) {
        $str = [];
        ksort($params);
        foreach($params as $k => $v) {
            $str[] = "$k=$v";
        }
        $str = implode('&', $str);
        $key = base64_decode($this->secretKey);

        $hash = hash_hmac('sha1', $str, $key, true);
        return base64_encode($hash);
    }

    static function generateNonce($length = 24) {
        $alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';
        $nonce = '';
        for($i=0; $i < $length; $i++) {
            $p = random_int(0, strlen($alphabet)-1);
            $nonce .= $alphabet[$p];
        }
        return $nonce;
    }

}
