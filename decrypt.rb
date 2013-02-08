#!/usr/bin/env ruby
require 'openssl'
require 'base64'

private_key_file = File.read 'private_key.pem'
private_key = OpenSSL::PKey::RSA.new private_key_file, 'password'

cryptData = STDIN.read

decrypted = private_key.private_decrypt Base64.decode64(cryptData)

puts decrypted
