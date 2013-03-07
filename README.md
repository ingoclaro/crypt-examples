generate keys with:

```
openssl genrsa -des3 -out private_key.pem 2056
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

example key files provided, the passfrase of the private key is **password**


you can check signing running the sign_test scripts.


you can check encrypting and decrypting running the script with some input, for example:

```
echo "test message" | ./crypt.php | ./decrypt.rb
./java/encrypt.sh test | ./decrypt.rb
```

and you should get the plain message back.

