import { scrypt, randomFill, createCipheriv, randomBytes, createDecipheriv, scryptSync } from "crypto";
import { createReadStream, createWriteStream } from 'fs';
import { pipeline } from "stream";

interface AlgorithmInterface {
    encrypt(path: string, algorithm: string, password: string, parameters?: Options): Promise<void | Array<Buffer | Uint8Array>>;
    decrypt(path: string, algorithm: string, password: string, parameters?: Options): Promise<void>;
    encryptSync(path: string, algorithm: string, password: string, parameters?: Options): void | Error;
};

interface Options {
    salt: Buffer | Uint8Array | Uint8ClampedArray | Uint16Array | Uint32Array | Int8Array | Int16Array | Int32Array | BigUint64Array | BigInt64Array | Float32Array | Float64Array | string;
    iv: Uint8Array | Uint8ClampedArray | Uint16Array | Uint32Array | Int8Array | Int16Array | Int32Array | BigUint64Array | BigInt64Array | Float32Array | Float64Array | string;
}

class Algorithms implements AlgorithmInterface{
    private buffer: Buffer | null = null;
    private iv: Uint8Array | null = null;


    encrypt = (path: string, algorithm: string, password: string, parameters?: Options) => {
        const options = parameters ? parameters as Options : null;
        if( options && options.iv && options.salt ){
            return new Promise<void>((resolve, reject) => {
                scrypt(password, options.salt, 24, (err: Error | null, key: Buffer): void => {
                    if(err) reject(err);
                    const cipher = createCipheriv(algorithm, key, options.iv);
    
                    const input = createReadStream(path);
                    const output = createWriteStream(`${path}.enc`);
    
                    pipeline(input, cipher, output, (err: NodeJS.ErrnoException | null) => {
                        if(err) reject(err);
                        resolve();
                    });
                })
            })
        } else {
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
        }
    };

 
    decrypt = (path: string, algorithm: string, password: string, parameters?: Options) => {
        const options = parameters ? parameters as Options : null;
        if(options && options.iv && options.salt){
            return new Promise<void>((resolve, reject) => {
                scrypt(password, options.salt, 24, (err: Error | null, key: Buffer): void => {
                    if(err) reject(err);
                    const input = createReadStream(path);
                    const output = createWriteStream("text.txt");
                    const decipher = createDecipheriv(algorithm, key, options.iv);
    
                    pipeline(input, decipher, output, (err: NodeJS.ErrnoException | null) => {
                        if(err) reject(err);
                        resolve();
                    })
                })
            })
        } else {
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
        } 
    };

    encryptSync = (path: string, algorithm: string, password: string, parameters?: Options): void | Error => {
        try{
            const key = scryptSync(password, randomBytes(16), 24);
            randomFill(new Uint8Array(16), (err: Error | null, iv: Uint8Array) => {
                if(err) throw err;
                if(!this.iv) this.iv = iv;
                const cipher = createCipheriv(algorithm, key, iv);

                const input = createReadStream(path);
                const output = createWriteStream(`${path}.enc`);

                pipeline(input, cipher, output, (err: NodeJS.ErrnoException | null) => {
                    if(err) throw err;
                });
            })
        } catch (err: unknown) {
            return err as Error
        }
    };
};

export default Algorithms;