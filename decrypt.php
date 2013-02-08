#!/usr/bin/php
<?php
$config['private_key'] = 'file://./private_key.pem';
$config['passphrase'] = 'password';

$private_key = openssl_get_privatekey($config['private_key'], $config['passphrase']);

$cryptData = trim(fgets(STDIN));

$decrypted = '';
$ret = openssl_private_decrypt(base64_decode($cryptData), $decrypted, $private_key);

echo $decrypted;
