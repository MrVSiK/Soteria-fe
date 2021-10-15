# file-encryptor
An easy to use file encryption package for nodejs.

## Installation
```bash 
npm i file-encryptor 
```

## Quick Start
```js
const fe = require("file-encryptor");
```
## Async Encryption
**encrypt(file-path, password, options)** returns a **promise** which resolves with an object containing the salt and iv used to encrypt the file.
```js
const fe = require("file-encryptor");
fe.encrypt(<file path>, <password>, options).then(({ salt, iv }) => { // Code goes here});
```
## Sync Encryption
**encryptSync(file-path, password, options)** returns an object containing the salt and iv used to encrypt the file.
```js
const fe = require("file-encryptor");
const { salt, iv } = fe.encryptSync(<file path>, <password>, options);
```
## Async Decryption
**decrypt(file-path, password, options)** returns a **promise**.
```js
const fe = require("file-encryptor");
fe.decrypt(<file path>, <password>, options).then(() => { // Code goes here});
```
## Sync Decryption
**decryptSync(file-path, password, options)** returns nothing.
```js
const fe = require("file-encryptor");
fe.decryptSync(<file path>, <password>, options);
```

## Options

| Name | Description |
|------|-------------|
| bytes | Specify the number of bytes to be used to make the salt. _Default:- 16_ |
| algorithm | Specify the algorithm to encrypt/decrpyt a file. _Default:- aes-192-cbc_ |
| iv | Specify the Initialisation Vector. |
| salt | Specify the salt to make the cipher. |
| keylen | Specify the length(in bytes) of the key used to make cipher. _Default: 24_ |
| length | Specify the length of iv. _Default:- 16_ |
| outputPath | Specify the output file name. |
