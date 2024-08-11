<?php

class JWT
{
    public static function encode($payload, $key, $alg = 'HS256')
    {
        $header = json_encode(['typ' => 'JWT', 'alg' => $alg]);
        $base64UrlHeader = self::base64UrlEncode($header);
        $base64UrlPayload = self::base64UrlEncode(json_encode($payload));
        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $key, true);
        $base64UrlSignature = self::base64UrlEncode($signature);
        return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
    }

    public static function decode($jwt, $key, $alg = 'HS256')
    {
        list($base64UrlHeader, $base64UrlPayload, $base64UrlSignature) = explode('.', $jwt);
        $header = json_decode(self::base64UrlDecode($base64UrlHeader), true);
        if ($header['alg'] !== $alg) {
            throw new Exception('Algorithm not supported');
        }
        $payload = json_decode(self::base64UrlDecode($base64UrlPayload), true);
        $signature = self::base64UrlDecode($base64UrlSignature);
        $validSignature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $key, true);
        if ($signature !== $validSignature) {
            throw new Exception('Invalid signature');
        }
        return $payload;
    }

    private static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode($data)
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }
}
