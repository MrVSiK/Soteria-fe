import { scrypt, randomFill, createCipheriv, randomBytes, createDecipheriv } from "crypto";
import { createReadStream, createWriteStream } from 'fs';
import { pipeline } from "stream";

interface AESInterface {
    encrypt(path: string, algorithm: string, password: string): Promise<void>;
    encryptWithIv(path: string, algorithm: string, password: string, iv: Uint8Array): Promise<void>;
    decrypt(path: string, algorithm: string, password: string): Promise<void>;
    decryptWithIv(path: string, algorithm: string, password: string, iv: Uint8Array): Promise<void>;
};

class AES implements AESInterface{
    private buffer: Buffer | null = null;
    private iv: Uint8Array | null = null;


    encrypt = (path: string, algorithm: string, password: string) => {
        return new Promise<void>((resolve, reject) => {
            if(!this.buffer) this.buffer = randomBytes(16);
            scrypt(password, this.buffer, 24, (err: Error | null, key: Buffer): void => {
                if(err) reject(err);
                randomFill(new Uint8Array(16), (err: Error | null, iv: Uint8Array) => {
                    if(err) reject(err);
                    if(!this.iv) this.iv = iv;
                    const cipher = createCipheriv(algorithm, key, iv);

                    const input = createReadStream(path);
                    const output = createWriteStream(`${path}.enc`);

                    pipeline(input, cipher, output, (err: NodeJS.ErrnoException | null) => {
                        if(err) reject(err);
                        resolve();
                    });
                })
            })
        })
    };


    encryptWithIv = (path: string, algorithm: string, password: string, iv: Uint8Array) => {
        return new Promise<void>((resolve, reject) => {
            this.buffer = randomBytes(16);
            scrypt(password, this.buffer, 24, (err: Error | null, key: Buffer): void => {
                if(err) reject(err);
                this.iv = iv;
                const cipher = createCipheriv(algorithm, key, iv);

                const input = createReadStream(path);
                const output = createWriteStream(`${path}.enc`);

                pipeline(input, cipher, output, (err: NodeJS.ErrnoException | null) => {
                    if(err) reject(err);
                    resolve();
                });
            })
        })
    };

 
    decrypt = (path: string, algorithm: string, password: string) => {
        return new Promise<void>((resolve, reject) => {
            scrypt(password, this.buffer as Buffer, 24, (err: Error | null, key: Buffer): void => {
                if(err) reject(err);
                const input = createReadStream(path);
                const output = createWriteStream("text.txt");
                const decipher = createDecipheriv(algorithm, key, this.iv);

                pipeline(input, decipher, output, (err: NodeJS.ErrnoException | null) => {
                    if(err) reject(err);
                    resolve();
                })
            })
        })  
    };


    decryptWithIv = (path: string, algorithm: string, password: string, iv: Uint8Array) => {
        return new Promise<void>((resolve, reject) => {
            scrypt(password, this.buffer as Buffer, 24, (err: Error | null, key: Buffer): void => {
                if(err) reject(err);
                const input = createReadStream(path);
                const output = createWriteStream("text.txt");
                const decipher = createDecipheriv(algorithm, key, iv);

                pipeline(input, decipher, output, (err: NodeJS.ErrnoException | null) => {
                    if(err) reject(err);
                    resolve();
                })
            })
        })
    };
};

export default AES;