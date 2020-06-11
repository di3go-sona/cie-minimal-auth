#! /bin/sh
/usr/local/opt/openssl/bin/openssl cms -in EF.SOD.pkcs7  -inform DER -verify -no_attr_verify -CAfile ItalyCA-3.cert 
