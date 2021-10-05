import {
  scrypt,
  randomFill,
  createCipheriv,
  randomBytes,
  createDecipheriv,
  scryptSync,
  randomFillSync
} from 'crypto';
import { createReadStream, createWriteStream } from 'fs';
import { pipeline } from 'stream';
import type { BinaryLike } from '../types/index';
import { dirname, extname, basename, join } from 'path';

type Options = {
    bytes?: number,
    algorithm?: string,
    iv?: BinaryLike,
    salt?: BinaryLike | Buffer,
    keylen?: number,
    length?: number,
    outputPath?: string
}

type Object = {
    salt: BinaryLike | Buffer,
    iv: BinaryLike
}

const encrypt = (path: string, password: string, options?: Options) => {
    return new Promise<Object>((resolve, reject) => {
        const salt = options?.salt ? options.salt : randomBytes(options?.bytes ? options.bytes : 16);
        const keylen = options?.keylen ? options.keylen : 24;
        const algorithm = options?.algorithm ? options.algorithm : 'aes-192-cbc';
        const length = options?.length ? options.length : 16;
        scrypt(password, salt, keylen, (err, key) => {
            if(err) reject(err);
            randomFill(new Uint8Array(length), (err, iv) => {
                if(err) reject(err);
                const trueIv = options?.iv ? options.iv : iv;
                const cipher = createCipheriv(algorithm, key, trueIv);

                const input = createReadStream(path);
                const fileName = basename(path, extname(path));
                const dirPath = dirname(path);
                const outputPath = options?.outputPath ? options.outputPath : join(dirPath, `${fileName}.enc${extname(path)}`);
                const output = createWriteStream(outputPath);

                pipeline(input, cipher, output, (err) => {
                    if(err) reject(err);
                    resolve({
                        salt: salt,
                        iv: trueIv
                    });
                })
            })
        })
    })
};


const decrypt = (path: string, password: string, options?: Options) => {
    return new Promise<void>((resolve, reject) => {
        const salt = options?.salt ? options.salt : undefined;
        const keylen = options?.keylen ? options.keylen : 24;
        const algorithm = options?.algorithm ? options.algorithm : 'aes-192-cbc';
        const iv = options?.iv ? options.iv : undefined;
        scrypt(password, salt as BinaryLike, keylen, (err, key) => {
            if(err) reject(err);
            const cipher = createDecipheriv(algorithm, key, iv as BinaryLike);

            const input = createReadStream(path);
            const fileName = basename(path, `.enc${extname(path)}`);
            const dirPath = dirname(path);
            const outputPath = options?.outputPath ? options.outputPath : join(dirPath, `${fileName}${extname(path)}`);
            const output = createWriteStream(outputPath);

            pipeline(input, cipher, output, (err) => {
                if(err) reject(err);
                resolve();
            })
        })
    })
};

const encryptSync = (path: string, password: string, options?: Options) => {
    try{
        const salt = options?.salt ? options.salt : randomBytes(options?.bytes ? options.bytes : 16);
        const keylen = options?.keylen ? options.keylen : 24;
        const algorithm = options?.algorithm ? options.algorithm : 'aes-192-cbc';
        const length = options?.length ? options.length : 16;
        const iv = options?.iv ? options.iv : randomFillSync(new Uint32Array(length));
        
        const key = scryptSync(password, salt, keylen);
        const cipher = createCipheriv(algorithm, key, iv);

        const input = createReadStream(path);
        const fileName = basename(path, extname(path));
        const dirPath = dirname(path);
        const outputPath = options?.outputPath ? options.outputPath : join(dirPath, `${fileName}.enc${extname(path)}`);
        const output = createWriteStream(outputPath);
        
        pipeline(input, cipher, output, (err) => {
            if(err) throw err;
        });
        
        return {
            salt: salt,
            iv: iv
        }
    } catch (err) {
        console.log(err);
        process.exit(1);
    }
};

const decryptSync = (path: string, password: string, options?: Options) => {
    try{
        const salt = options?.salt ? options.salt : undefined;
        const keylen = options?.keylen ? options.keylen : 24;
        const algorithm = options?.algorithm ? options.algorithm : 'aes-192-cbc';
        
        const key = scryptSync(password, salt as BinaryLike, keylen);
        const iv = options?.iv ? options.iv : undefined;
        const cipher = createDecipheriv(algorithm, key, iv as BinaryLike);

        const input = createReadStream(path);
        const fileName = basename(path, `.enc${extname(path)}`);
        const dirPath = dirname(path);
        const outputPath = options?.outputPath ? options.outputPath : join(dirPath, `${fileName}${extname(path)}`);
        const output = createWriteStream(outputPath);
        
        pipeline(input, cipher, output, (err) => {
            if(err) throw err;
        });
    } catch (err) {
        console.log(err);
        process.exit(1);
    }
};

export default {
    encrypt,
    decrypt,
    encryptSync,
    decryptSync
}