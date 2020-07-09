<?php

namespace Regzen;

use Exception;
use GuzzleHttp\Client;

class RegzenClient
{
    const CIPHER = 'AES-256-CBC';

    const REGZEN_SECRET_ENV_KEY = 'REGZEN_APPLICATION_SECRET';

    const EXCHANGE_ENDPOINT_URL = 'oauth/exchange';

    public function __construct($applicationSecret, $apiBaseUrl = 'https://api.regzen.com/api/')
    {
        if (!$applicationSecret) {
            throw new RegzenApplicationSecretNotFoundException(
                "Please provide your application secret."
            );
        }

        $this->applicationSecret = $applicationSecret;
        $this->httpClient = new Client(['base_uri' => $apiBaseUrl]);
    }

    public function exchangeAuthorizationCode($authorizationCode)
    {
        try {
            $response = $this->httpClient->post(
                self::EXCHANGE_ENDPOINT_URL,
                [
                    'form_params' => [
                        'authorization_code' => $authorizationCode
                    ],
                ]
            );
        } catch (Exception $exception) {
            throw new RegzenUnauthorizedException;
        }

        $responseJson = json_decode($response->getBody());

        if (!$stringifiedUserData = $this->decrypt($responseJson->data)) {
            throw new RegzenUnauthorizedException;
        }

        return (object) [
            'data' => json_decode($stringifiedUserData),
        ];
    }

    public function decryptPayload($encryptedPayload)
    {
        if (!$stringifiedData = $this->decrypt($encryptedPayload)) {
            throw new RegzenUnauthorizedException;
        }

        return (object) [
            'data' => json_decode($stringifiedData),
        ];
    }

    private function decrypt($data)
    {
        $c = base64_decode($data);
        $ivLength = openssl_cipher_iv_length($cipher = self::CIPHER);
        $iv = substr($c, 0, $ivLength);
        $hmac = substr($c, $ivLength, $sha2len = 32);
        $cipherText = substr($c, $ivLength + $sha2len);
        $plainText = openssl_decrypt(
            $cipherText,
            $cipher,
            $this->applicationSecret,
            $options = OPENSSL_RAW_DATA,
            $iv
        );

        $calcmac = hash_hmac('sha256', $cipherText, $this->applicationSecret, $as_binary = true);

        if (!hash_equals($hmac, $calcmac)) {
            return false;
        }

        return $plainText;
    }
}
