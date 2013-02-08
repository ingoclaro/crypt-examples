#!/usr/bin/env ruby
require 'openssl'
require 'base64'

public_key = OpenSSL::PKey::RSA.new File.read 'public_key.pem'

message = STDIN.read

cryptData = public_key.public_encrypt message
cryptData = Base64.encode64(cryptData).gsub(/\n/, "")

puts cryptData
