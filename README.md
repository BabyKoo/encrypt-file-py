## Usage

```sh
python ./aes-encrypt-file.py [-h] -p PASSWORD [-e] [-d] -f FILENAME
```

## Description

A python script for encrypt or decrypt a file with AES.

### options

- -h, --help: show this help message and exit
- -p PASSWORD, --password PASSWORD: the password to encrypt or decrypt the file
- -e, --encrypt: to encrypt the file
- -d, --decrypt: to decrypt the file
- -f FILENAME, --filename FILENAME: the name of the file to encrypt or decrypt

## Structure

### Encrypted data

| Field                  | Length(Byte) | Detail                              |
| ---------------------- | ------------ | ----------------------------------- |
| IV                     | 16           | AES initialization vector.          |
| Time stamp             | 16           | Plain text, be used for hash salt. |
| Origin File hash value | 32           |                                     |
| Cipherdata             | Variable     |                                     |
