#!/usr/bin/env ruby
require 'openssl'
require 'base64'

def hex2bin hex
  [hex].pack "H*"
end

private_key_file = File.read 'private_key.pem'
private_key = OpenSSL::PKey::RSA.new private_key_file, 'password'

cryptData = STDIN.read

decrypted = private_key.private_decrypt hex2bin(cryptData.strip)

puts decrypted
