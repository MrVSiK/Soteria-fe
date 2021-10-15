"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var crypto_1 = require("crypto");
var fs_1 = require("fs");
var stream_1 = require("stream");
var path_1 = require("path");
var encrypt = function (path, password, options) {
    return new Promise(function (resolve, reject) {
        var salt = (options === null || options === void 0 ? void 0 : options.salt) ? options.salt : (0, crypto_1.randomBytes)((options === null || options === void 0 ? void 0 : options.bytes) ? options.bytes : 16);
        var keylen = (options === null || options === void 0 ? void 0 : options.keylen) ? options.keylen : 24;
        var algorithm = (options === null || options === void 0 ? void 0 : options.algorithm) ? options.algorithm : 'aes-192-cbc';
        var length = (options === null || options === void 0 ? void 0 : options.length) ? options.length : 16;
        (0, crypto_1.scrypt)(password, salt, keylen, function (err, key) {
            if (err)
                reject(err);
            (0, crypto_1.randomFill)(new Uint8Array(length), function (err, iv) {
                if (err)
                    reject(err);
                var trueIv = (options === null || options === void 0 ? void 0 : options.iv) ? options.iv : iv;
                var cipher = (0, crypto_1.createCipheriv)(algorithm, key, trueIv);
                var input = (0, fs_1.createReadStream)(path);
                var fileName = (0, path_1.basename)(path, (0, path_1.extname)(path));
                var dirPath = (0, path_1.dirname)(path);
                var outputPath = (options === null || options === void 0 ? void 0 : options.outputPath) ? options.outputPath : (0, path_1.join)(dirPath, fileName + ".enc" + (0, path_1.extname)(path));
                var output = (0, fs_1.createWriteStream)(outputPath);
                (0, stream_1.pipeline)(input, cipher, output, function (err) {
                    if (err)
                        reject(err);
                    resolve({
                        salt: salt,
                        iv: trueIv
                    });
                });
            });
        });
    });
};
var decrypt = function (path, password, options) {
    return new Promise(function (resolve, reject) {
        var salt = options.salt ? options.salt : undefined;
        var keylen = options.keylen ? options.keylen : 24;
        var algorithm = options.algorithm ? options.algorithm : 'aes-192-cbc';
        var iv = options.iv ? options.iv : undefined;
        (0, crypto_1.scrypt)(password, salt, keylen, function (err, key) {
            if (err)
                reject(err);
            var cipher = (0, crypto_1.createDecipheriv)(algorithm, key, iv);
            var input = (0, fs_1.createReadStream)(path);
            var fileName = (0, path_1.basename)(path, ".enc" + (0, path_1.extname)(path));
            var dirPath = (0, path_1.dirname)(path);
            var outputPath = (options === null || options === void 0 ? void 0 : options.outputPath) ? options.outputPath : (0, path_1.join)(dirPath, "" + fileName + (0, path_1.extname)(path));
            var output = (0, fs_1.createWriteStream)(outputPath);
            (0, stream_1.pipeline)(input, cipher, output, function (err) {
                if (err)
                    reject(err);
                resolve();
            });
        });
    });
};
var encryptSync = function (path, password, options) {
    try {
        var salt = (options === null || options === void 0 ? void 0 : options.salt) ? options.salt : (0, crypto_1.randomBytes)((options === null || options === void 0 ? void 0 : options.bytes) ? options.bytes : 16);
        var keylen = (options === null || options === void 0 ? void 0 : options.keylen) ? options.keylen : 24;
        var algorithm = (options === null || options === void 0 ? void 0 : options.algorithm) ? options.algorithm : 'aes-192-cbc';
        var length_1 = (options === null || options === void 0 ? void 0 : options.length) ? options.length : 16;
        var iv = (options === null || options === void 0 ? void 0 : options.iv) ? options.iv : (0, crypto_1.randomFillSync)(new Uint8Array(length_1));
        var key = (0, crypto_1.scryptSync)(password, salt, keylen);
        var cipher = (0, crypto_1.createCipheriv)(algorithm, key, iv);
        var input = (0, fs_1.createReadStream)(path);
        var fileName = (0, path_1.basename)(path, (0, path_1.extname)(path));
        var dirPath = (0, path_1.dirname)(path);
        var outputPath = (options === null || options === void 0 ? void 0 : options.outputPath) ? options.outputPath : (0, path_1.join)(dirPath, fileName + ".enc" + (0, path_1.extname)(path));
        var output = (0, fs_1.createWriteStream)(outputPath);
        (0, stream_1.pipeline)(input, cipher, output, function (err) {
            if (err)
                throw err;
        });
        return {
            salt: salt,
            iv: iv
        };
    }
    catch (err) {
        console.log(err);
        process.exit(1);
    }
};
var decryptSync = function (path, password, options) {
    try {
        var salt = (options === null || options === void 0 ? void 0 : options.salt) ? options.salt : undefined;
        var keylen = (options === null || options === void 0 ? void 0 : options.keylen) ? options.keylen : 24;
        var algorithm = (options === null || options === void 0 ? void 0 : options.algorithm) ? options.algorithm : 'aes-192-cbc';
        var key = (0, crypto_1.scryptSync)(password, salt, keylen);
        var iv = (options === null || options === void 0 ? void 0 : options.iv) ? options.iv : undefined;
        var cipher = (0, crypto_1.createDecipheriv)(algorithm, key, iv);
        var input = (0, fs_1.createReadStream)(path);
        var fileName = (0, path_1.basename)(path, ".enc" + (0, path_1.extname)(path));
        var dirPath = (0, path_1.dirname)(path);
        var outputPath = (options === null || options === void 0 ? void 0 : options.outputPath) ? options.outputPath : (0, path_1.join)(dirPath, "" + fileName + (0, path_1.extname)(path));
        var output = (0, fs_1.createWriteStream)(outputPath);
        (0, stream_1.pipeline)(input, cipher, output, function (err) {
            if (err)
                throw err;
        });
    }
    catch (err) {
        console.log(err);
        process.exit(1);
    }
};
module.exports = {
    encrypt: encrypt,
    decrypt: decrypt,
    encryptSync: encryptSync,
    decryptSync: decryptSync
};
//# sourceMappingURL=index.js.map