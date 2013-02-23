#!/usr/bin/php
<?php
$config['private_key'] = 'file://./private_key.pem';
$config['passphrase'] = 'password';

$private_key = openssl_get_privatekey($config['private_key'], $config['passphrase']);
if($private_key === false) {
	die('error loading private key');
}

$cryptData = trim(fgets(STDIN));

$decrypted = '';
$ret = openssl_private_decrypt(base64_decode($cryptData), $decrypted, $private_key);
if($ret === false) {
	die('error decrypting string');
}

echo $decrypted;
