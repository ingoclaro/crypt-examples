<?php
$config['private_key'] = 'file://./private_key.pem';
$config['passphrase'] = 'password';
$config['public_key'] = 'file://./public_key.pem';

$private_key = openssl_get_privatekey($config['private_key'], $config['passphrase']);
$public_key = openssl_get_publickey($config['public_key']);

$message = 'This is my message';

echo "message:\n$message\n\n";

echo "sign test:\n";
signTest($message, $private_key, $public_key);

function signTest($message, $private_key, $public_key) {
	$signature = '';

	$ret = openssl_sign($message, $signature, $private_key);
	if($ret === false) {
		die('error signing');
	}
	$signature = base64_encode($signature);

	echo "signature:\n";
	echo $signature . "\n\n";

	// verify signature
	$ret = openssl_verify($message, base64_decode($signature), $public_key);

	switch($ret) {
		case 1:
			echo "signature ok!\n";
		break;
		case -1:
			die("error verifying signature\n");
		break;
		default:
			echo "signature didn't match\n";
		break;
	}
}
