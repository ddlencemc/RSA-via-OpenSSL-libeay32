# RSA via OpenSSL libeay32
Реализация шифрования/дешифрование строки алгоритмом RSA через библиотеку [openssl](https://www.openssl.org/) с указанием файлов секретного и публичного ключа в формате PEM.

При ключе 1024 бит длина строки при **RSA_PKCS1_PADDING** = 117 байт, при **RSA_NO_PADDING** максимальная длина строки = 128 байт
При увеличении битности ключа увеличивается длина строки для шифрования.


Для компиляции в **XE** необходимо поменять типы у входящих параметров

####Delphi7:
```delphi
function LoadPrivateKey(KeyFile: string): pEVP_PKEY;
function LoadPublicKey(KeyFile: string): pEVP_PKEY;
```
####XE:
```delphi
function LoadPrivateKey(KeyFile: AnsiString): pEVP_PKEY;
function LoadPublicKey(KeyFile: AnsiString): pEVP_PKEY;
```

####Автор
Иван Лодяной (ddlencemc@gmail.com)
