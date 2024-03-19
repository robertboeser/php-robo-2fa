<?php
namespace Robo\Robo2fa;

class HOTP {
    protected $algo;
    protected $length = 6;      // 6-10
    protected $secret = '';

    function __construct($algo = 'sha1') {
        $this->algo = $algo;
    }

    function setSecret($secret) {
        $length = strlen($secret);
        if($length & 0x03) throw new \Exception('Secret length must be a multiple of 8');
        $this->secret = $secret;
    }

    protected function generateRawHash($count) {
        $count = pack('J', $count);
        return hash_hmac($this->algo, $count, $this->secret, true);
    }

    protected function truncate($raw_hash) {
        $offset = ord($raw_hash[-1]) & 0xf;
        return unpack('Nint', $raw_hash, $offset)['int'] & 0x7fffffff;
    }

    function generateToken($count) {
        $hash = $this->generateRawHash($count);
        $code = $this->truncate($hash);
        $code = $code % pow(10, $this->length);
        return str_pad($code, $this->length, "0", STR_PAD_LEFT);
    }

    static function generateSecret($length = 16) {
        if($length & 0x03) throw new \Exception('Secret length must be a multiple of 8');
        return random_bytes($length);
    }
}
