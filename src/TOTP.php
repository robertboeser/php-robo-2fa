<?php
namespace Robo\Robo2fa;

use SKleeschulte\Base32;

class TOTP extends HOTP {
    protected $t0 = 0;          // start time
    protected $tx = 30;         // interval

    function setTimeParams($start, $interval) {
        $this->t0 = $start;
        $this->tx = $interval;
    }

    function generateToken($_ = null) {
        $count = $this->getCounter();
        //echo "count: $count\n";
        return parent::generateToken($count);
    }

    protected function getCounter($time = null) {
        if(is_null($time)) $time = time();
        return floor(($time - $this->t0) / $this->tx);
    }

    static function generateQrCode($issuer, $label, $secret) {
        $iss = urlencode($issuer);
        $lbl = urlencode($label);
        $secret = Base32::encodeByteStr($secret, true);
        $query = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
        ]);
        return "otpauth://totp/$iss:$lbl?$query";
    }
}
