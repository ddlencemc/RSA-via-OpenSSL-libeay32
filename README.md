# RSA-via-OpenSSL-libeay32
Реализация шифрования/дешифрование строки алгоритмом RSA через библиотеку openssl с указанием файлов секретного и публичного ключа в формате PEM.
При ключе 1024 бит длина строки при RSA_PKCS1_PADDING = 117 байт, при RSA_NO_PADDING максимальная длина строки = 128 байт
При увеличении битности ключа увеличивается длина строки для шифрования.

В компилировании на XE необходимо поменять типы у входящих параметров

Delphi7:
function LoadPrivateKey(KeyFile: string): pEVP_PKEY;
function LoadPublicKey(KeyFile: string): pEVP_PKEY;

XE:
function LoadPrivateKey(KeyFile: AnsiString): pEVP_PKEY;
function LoadPublicKey(KeyFile: AnsiString): pEVP_PKEY;
