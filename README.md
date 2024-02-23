## Usage

```shell
python ./aes-encrypt-file.py [-h] -p PASSWORD [-e] [-d] -f FILENAME [-v VERSION] [-r {True,False}]
```

## Description

A python script for encrypt or decrypt a file with AES.

### options

- -h, --help: show this help message and exit
- -p PASSWORD, --password PASSWORD: the password to encrypt or decrypt the file
- -e, --encrypt: to encrypt the file
- -d, --decrypt: to decrypt the file
- -f FILENAME, --filename FILENAME: the name of the file to encrypt or decrypt
- -v VERSION, --version VERSION: the version number of the encryption method
- -r {True,False}, --remove {True,False}: to purge the origin file from File System while encrypting

## Structure

### Encrypted data

| Field                  | Length(Byte) | Detail                                    |
| ---------------------- | ------------ | ----------------------------------------- |
| Version                | 1            | The First-level version number.           |
| IV                     | 16           | AES initialization vector.                |
| Time stamp             | 16           | Plain text(ASCII), be used for hash-salt. |
| Origin File hash value | 32           | SHA-256 value.                            |
| Cipherdata             | Variable     |                                           |
