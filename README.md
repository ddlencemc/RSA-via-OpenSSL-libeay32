# RSA via OpenSSL libeay32 on Delphi / RAD Studio / Embarcadero

### Описание

Реализация шифрования/дешифрование строки алгоритмом RSA через библиотеку [openssl](https://www.openssl.org/) с указанием файлов секретного и публичного ключа в формате PEM.

При ключе 1024 бит длина строки при **RSA_PKCS1_PADDING** = 117 байт, при **RSA_NO_PADDING** максимальная длина строки = 128 байт
При увеличении битности ключа увеличивается длина строки для шифрования.

Текущая версия исправлена и корректно работает после компиляции в EXE версииях и выше



### Decription

Implementation of encryption / decryption of a string using the RSA algorithm through the openssl library, specifying the secret and public key files in PEM format.

With the 1024 bit key, the string length with **RSA_PKCS1_PADDING** = 117 bytes, with **RSA_NO_PADDING**, the maximum string length = 128 bytes. Increasing the key bit increases the encryption string length.
The current version has been fixed and works correctly after compilation in XE versions and higher


*Generate private key*

    openssl genrsa 1024 > private.pem

*Generate public key from private*

    openssl rsa -in private.pem -pubout > public.pem
    
### Souce Code

*Init*

```delphi
OpenSSL_add_all_algorithms;
OpenSSL_add_all_ciphers;
OpenSSL_add_all_digests;
ERR_load_crypto_strings;
ERR_load_RSA_strings;
```

*Destroy*

```delphi
EVP_cleanup;
ERR_free_strings;
```

### Encrypt with the private key in PEM format

```delphi
{Шифрование/дешифрование flen размера буфера from в буфер _to используя структуру RSA ключа загруженного ранее в режиме выравнивания 
данных padding. Получаем длину шифрованного/дешифрованного буфера или -1 при ошибке
Шифрование публичным ключом}

function RSA_private_encrypt(flen: integer; from: PCharacter; _to: PCharacter; rsa: pRSA; padding: integer): integer; cdecl;
```

### Decrypt with the publick key in PEM format
```delphi
{Дешифрование публичным ключом}
function RSA_public_decrypt(flen: integer; from: PCharacter; _to: PCharacter; rsa: pRSA; padding: integer): integer; cdecl;
```

### Encrypt with the publick key in PEM format
```delphi
{Шифрование публичным ключом}
function RSA_public_encrypt(flen: integer; from: PCharacter; _to: PCharacter; rsa: pRSA; padding: integer): integer; cdecl;
```

### Decrypt with the private key in PEM format
```delphi
{Дешифрование секретным ключом}
function RSA_private_decrypt(flen: integer; from: PCharacter; _to: PCharacter; rsa: pRSA; padding: integer): integer; cdecl;
```

## Examples

*KeyFile – пусть до ключа/path key ('C:\key.pem'):*

```delphi
function LoadPublicKey(KeyFile: string) :pEVP_PKEY ;
var
  mem: pBIO;
  k: pEVP_PKEY;
begin
  k:=nil;
  mem := BIO_new(BIO_s_file()); //BIO типа файл
  BIO_read_filename(mem, PAnsiChar(KeyFile)); // чтение файла ключа в BIO
  try
    result := PEM_read_bio_PUBKEY(mem, k, nil, nil); //преобразование BIO  в структуру pEVP_PKEY, третий параметр указан nil, означает для ключа не нужно запрашивать пароль
  finally
    BIO_free_all(mem);
  end;
end;

function LoadPrivateKey(KeyFile: string) :pEVP_PKEY;
var
  mem: pBIO;
  k: pEVP_PKEY;
begin
  k := nil;
  mem := BIO_new(BIO_s_file());
  BIO_read_filename(mem, PAnsiChar(KeyFile));
  try
    result := PEM_read_bio_PrivateKey(mem, k, nil, nil);
  finally
    BIO_free_all(mem);
  end;
end;
```

```delphi
var
FPublicKey: pEVP_PKEY;
FPrivateKey: pEVP_PKEY;
err: Cardinal;
…
FPublicKey := LoadPublicKey(‘C:\public.key’); 
FPrivateKey := LoadPrivateKey(‘C:\private.key’);
 
 //if FPrivateKey = nil then // если ключ не вернулся, то читаем ошибку
if FPublicKey = nil then   
begin
	err := ERR_get_error;
	repeat
		log.Lines.Add(string(ERR_error_string(err, nil)));
		err := ERR_get_error;
	until err = 0;
	end;
```

## Example - Encrypt with the PEM-public key*

```delphi
var
	rsa: pRSA; // структура RSA
	size: Integer;
	FCryptedBuffer: pointer; // Выходной буфер 
	b64, mem: pBIO; 
	str, data: AnsiString; 
	len, b64len: Integer; 
	penc64: PAnsiChar;
	size: Integer;
	err: Cardinal
begin
	rsa := EVP_PKEY_get1_RSA(FPrivateKey); // Получение RSA структуры
	EVP_PKEY_free(FPrivateKey); // Освобождение pEVP_PKEY
	size := RSA_size(rsa); // Получение размера ключа
	GetMem(FCryptedBuffer, size); // Определение размера выходящего буфера
	str := AnsiString(‘Some text to encrypt’); // Строка для шифрования

	//Шифрование
	len := RSA_public_encrypt(Length(str),  // Размер строки для шифрования
							  PAnsiChar(str),  // Строка шифрования
							  FCryptedBuffer,  // Выходной буфер
							  rsa, // Структура ключа
							  RSA_PKCS1_PADDING // Определение выравнивания
							  );

	if len > 0 then // длина буфера после шифрования
	  begin
	  // полученный бинарный буфер преобразуем в человекоподобный base64
		b64 := BIO_new(BIO_f_base64); // BIO типа base64
		mem := BIO_push(b64, BIO_new(BIO_s_mem)); // Stream
		try
			BIO_write(mem, FCryptedBuffer, len); // Запись в Stream бинарного выходного буфера
			BIO_flush(mem);
			b64len := BIO_get_mem_data(mem, penc64); //получаем размер строки в base64
			SetLength(data, b64len); // задаем размер выходному буферу
			Move(penc64^, PAnsiChar(data)^, b64len); // Перечитываем в буфер data строку в base64 
		finally
			BIO_free_all(mem);
		end;
	  end
	  else
	  begin // читаем ошибку, если длина шифрованной строки -1
		err := ERR_get_error;
		repeat
			log.Lines.Add(string(ERR_error_string(err, nil)));
			err := ERR_get_error;
		until err = 0;
	  end;
	RSA_free(rsa);
end;
```

## Example - Decrypt result with the PEM-private key*
```delphi
var
  rsa: pRSA;
  out_: AnsiString;
  str, data: PAnsiChar;
  len, b64len: Integer;
  penc64: PAnsiChar;
  b64, mem, bio_out, bio: pBIO;
  size: Integer;
  err: Cardinal;
begin
	//ACryptedData : string; // Строка в base64
	rsa := EVP_PKEY_get1_RSA(FPublicKey);
	size := RSA_size(rsa);
	GetMem(data, size);  // Определяем размер выходному буферу дешифрованной строки
	GetMem(str, size); // Определяем размер шифрованному буферу после конвертации из base64

	//Decode base64
	b64 := BIO_new(BIO_f_base64);
	mem := BIO_new_mem_buf(PAnsiChar(ACryptedData), Length(ACryptedData));
	BIO_flush(mem);
	mem := BIO_push(b64, mem);
	BIO_read(mem, str , Length(ACryptedData)); // Получаем шифрованную строку в бинарном виде
	BIO_free_all(mem);
	// Дешифрование
	len := RSA_private_decrypt(size, PAnsiChar(str), data, rsa, RSA_PKCS1_PADDING);
	if len > 0 then
	begin	
	// в буфер data данные расшифровываются с «мусором» в конца, очищаем, определяем размер переменной out_ и переписываем в нее нужное количество байт из data
		SetLength(out_, len); 
		Move(data^, PAnsiChar(out_ )^, len);
	end
	else
    begin // читаем ошибку, если длина шифрованной строки -1
		err := ERR_get_error;
		repeat
			log.Lines.Add(string(ERR_error_string(err, nil)));
			err := ERR_get_error;
		until err = 0;
	end;
end;

```

## Example - Included private/public key 

```delphi
var
  mem, keybio: pBIO;
  k: pEVP_PKEY;
  keystring: AnsiString;
begin
  keystring :=
  '-----BEGIN RSA PRIVATE KEY-----' + #10 +
  'MIICXgIBAAKBgQCfydli2u2kJfb2WetkOekjzQIg7bIuU7AzAlBUPuA72UYXWnQ/' + #10 +
  'XcdSzEEMWSBLP7FO1vyVXR4Eb0/WqthF0ZViOK5bCN9CnR/1GMMiSqmIdByv/gUe' + #10 +
  'Z/UjGrKmxeQOoa2Yt0MJC64cNXgnKmYC7ui3A12LlvNdBBEF3WpcDbv+PQIDAQAB' + #10 +
  'AoGBAJnxukKHchSHjxthHmv9byRSyw42c0g20LcUL5g6y4Zdmi29s+moy/R1XOYs' + #10 +
  'p/RXdNfkQI0WnWjgZScIij0Z4rSs39uh7eQ5qxK+NH3QIWeR2ZNIno9jAXPn2bkQ' + #10 +
  'odS8FPzbZM9wHhpRvKW4FNPXqTc3ZkTcxi4zOwOdlECf9G+BAkEAzsJHgW1Isyac' + #10 +
  'I61MDu2qjMUwOdOBYS8GwEBfi/vbn/duwZIBXG/BZ7Pn+cBwImfksEXwx0MTkgF3' + #10 +
  'gyaChUSu+QJBAMXX3d94TwcF7lG9zkzc+AR/Onl4Z5UAb1GmUV57oYIFVgW1RIOk' + #10 +
  'vqynXWrTjTOg9C9j+VEpBG67LcnkwU16JmUCQH7pukKz9kAhnw43PcycDmhCUgvs' + #10 +
  'zCn/V8GCwiOHAZT7qLyhBrzazHj/cZFYknxMEZAyHk3x2n1w8Q9MACoVsuECQQDF' + #10 +
  'U7cyara31IyM7vlS5JpjMdrKyPLXRKXDFFXYHQtLubLA4rlBbBHZ9txP7kzJj+G9' + #10 +
  'WsOS1YxcPUlAM28xrYGZAkEArVKJHX4dF8UUtfvyv78muXJZNXTwmaaFy02xjtR5' + #10 +
  'uXWT1QjVN2a6jv6AW7ukXiSoE/spgfvdoriMk2JSs88nUw==' + #10 +
  '-----END RSA PRIVATE KEY-----' ;
  k := nil;


  keybio := BIO_new_mem_buf(Pchar(keystring), -1);
  mem := BIO_new(BIO_s_mem());
  BIO_read(mem, PAnsiChar(keystring), length(PAnsiChar(keystring)));
  try
    result := PEM_read_bio_PrivateKey(keybio, k, nil, nil);
  finally
    BIO_free_all(mem);
  end;
end;
```

