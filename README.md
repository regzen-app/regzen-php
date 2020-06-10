# Regzen PHP Library

This library provides a simple interface for communicating with the Regzen API.

## Documentation

 - https://docs.regzen.com/

## Installation

The preferred method of installing this library is with
[Composer](https://getcomposer.org/) by running the following from your project
root:

    $ composer require regzen/regzen-php

## Usage

### Instantiating the client

Instantiate the client with your application secret:

    $regzen = new \Regzen\RegzenClient('YOUR_APPLICATION_SECRET');

*Note: You should not keep your application secret in your source code, but rather retrieve it as the value of an environment variable.*

### Exchanging the authorization code

Exchange the authorization code by calling `exchangeAuthorizationCode` on the client:

    $response = $this->regzen->exchangeAuthorizationCode($authorizationCode);

You can later acces the user data like this:

    $email = $response->data->email;

If the exchange fails, a `\Regzen\RegzenUnauthorizedException` will be thrown which you can catch and show the user appropriate feedback.

### Decrypting data

When communicating with the Regzen API, you'll need to decrypt received data before any further use.
Decrypt payload by calling `decryptPayload` on the client:

    $payload = $this->regzen->decryptPayload($encryptedPayload);

You can later acces the payload data like this:

    $fieldName = $payload->data->field_name;

If the decryption fails, a `\Regzen\RegzenUnauthorizedException` will be thrown which you can catch and show the user appropriate feedback.
