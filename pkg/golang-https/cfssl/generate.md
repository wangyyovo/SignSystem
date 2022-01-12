### 证书生成步骤
```shell
# 生成根证书
$ cfssl gencert -initca ca-csr.json | cfssljson -bare ca -
# 签发server证书
$ cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=server server-csr.json | cfssljson -bare server
# 签发client 证书
$ cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client client-csr.json | cfssljson -bare client
```


```shell
# 生成根证书
$ cfssl_windows-amd64.exe gencert -initca ca-csr.json | cfssljson_windows-amd64.exe -bare ca -
# 签发server证书
$ cfssl_windows-amd64.exe gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=server server-csr.json | cfssljson_windows-amd64.exe -bare server
# 签发client 证书
$ cfssl_windows-amd64.exe gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client client-csr.json | cfssljson_windows-amd64.exe -bare client
```

openssl x509 -sha256 -fingerprint -noout -in public_key.pem
openssl x509 -in 214344674390250.pem -noout -text

