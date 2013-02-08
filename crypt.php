#!/usr/bin/php
<?php
$config['public_key'] = 'file://./public_key.pem';

$public_key = openssl_get_publickey($config['public_key']);

$message = trim(fgets(STDIN));

$cryptData = '';
$ret = openssl_public_encrypt($message, $cryptData, $public_key);
if($ret === false) {
	die('failed to encrypt data');
}

$cryptData = base64_encode($cryptData);

echo $cryptData;
