require 'openssl'
require 'base64'

private_key_file = File.read 'private_key.pem'
private_key = OpenSSL::PKey::RSA.new private_key_file, 'password'
public_key = OpenSSL::PKey::RSA.new File.read 'public_key.pem'

message = 'This is my message'
puts "message:\n#{message}\n\n"

def sign_test(message, private_key, public_key)
  signature = private_key.sign OpenSSL::Digest::SHA1.new, message
  signature = Base64.encode64(signature).gsub(/\n/, "") #Base64 encode without newlines

  puts 'signature:'
  puts "#{signature}\n\n"

  valid = public_key.verify OpenSSL::Digest::SHA1.new, Base64.decode64(signature), message

  if valid
    puts 'signature ok!'
  else
    puts "signature didn't match"
  end
end

puts "sign test:\n"
sign_test(message, private_key, public_key)
