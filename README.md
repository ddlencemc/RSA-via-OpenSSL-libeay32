# RSA via OpenSSL libeay32 on Delphi / RAD Studio / Embarcadero
Реализация шифрования/дешифрование строки алгоритмом RSA через библиотеку [openssl](https://www.openssl.org/) с указанием файлов секретного и публичного ключа в формате PEM.

При ключе 1024 бит длина строки при **RSA_PKCS1_PADDING** = 117 байт, при **RSA_NO_PADDING** максимальная длина строки = 128 байт
При увеличении битности ключа увеличивается длина строки для шифрования.

Текущая версия исправлена и корректно работает после компиляции в EXE версииях и выше


Implementation of encryption / decryption of a string using the RSA algorithm through the openssl library, specifying the secret and public key files in PEM format.

With the 1024 bit key, the string length with **RSA_PKCS1_PADDING** = 117 bytes, with **RSA_NO_PADDING**, the maximum string length = 128 bytes. Increasing the key bit increases the encryption string length.
The current version has been fixed and works correctly after compilation in XE versions and higher


