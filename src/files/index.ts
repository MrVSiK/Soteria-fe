import { scrypt, randomFill, createCipheriv, randomBytes, createDecipheriv, scryptSync } from "crypto";
import { createReadStream, createWriteStream } from 'fs';
import { pipeline } from "stream";
import type {BinaryLike, ParameterReturn } from "../../types/index";

interface AlgorithmInterface {
    encrypt(path: string, algorithm?: string, password?: string, parameters?: Options): Promise<ParameterReturn>;
    decrypt(path: string, algorithm?: string, password?: string, parameters?: Options): Promise<void>;
    encryptSync(path: string, algorithm: string, password: string, parameters?: Options): ParameterReturn | Error;
    decryptSync(path: string, algorithm?: string, password?: string, parameters?: Options): void | Error;
};

interface Options {
    salt?: Buffer | BinaryLike,
    iv?: BinaryLike
}

class Encryptor implements AlgorithmInterface{
    public buffer: Buffer | null = null;
    public iv: BinaryLike | null = null;
    public password: string | null = null;
    public algorithm: string | null = null;

    constructor(password?: string, algorithm?: string){
        if(password) this.password = password;
        if(algorithm) this.algorithm = algorithm;
    }
    encrypt = (path: string, algorithm?: string, password?: string, parameters?: Options) => {
        const options = parameters ? parameters as Options : null;
        if( options && options.iv && options.salt ){
            return new Promise<ParameterReturn>((resolve, reject) => {
                scrypt(password ? password : this.password as string, options.salt as Buffer | BinaryLike, 24, (err: Error | null, key: Buffer): void => {
                    if(err) reject(err);
                    const cipher = createCipheriv(algorithm ? algorithm : this.algorithm as string, key, options.iv as BinaryLike);
    
                    const input = createReadStream(path);
                    const output = createWriteStream(`${path}.enc`);
    
                    pipeline(input, cipher, output, (err: NodeJS.ErrnoException | null) => {
                        if(err) reject(err);
                        resolve({
                            salt: this.buffer as Buffer,
                            iv: this.iv as BinaryLike
                        });
                    });
                })
            })
        } else if(options && options.iv && !options.salt){
            this.buffer = randomBytes(16);
            return new Promise<ParameterReturn>((resolve, reject) => {
                scrypt(password ? password : this.password as string, this.buffer as Buffer, 24, (err: Error | null, key: Buffer): void => {
                    if(err) reject(err);
                    const cipher = createCipheriv(algorithm ? algorithm : this.algorithm as string, key, options.iv as BinaryLike);
    
                    const input = createReadStream(path);
                    const output = createWriteStream(`${path}.enc`);
    
                    pipeline(input, cipher, output, (err: NodeJS.ErrnoException | null) => {
                        if(err) reject(err);
                        resolve({
                            salt: this.buffer as Buffer,
                            iv: this.iv as BinaryLike
                        });;
                    });
                })
            })
        } else if (options && !options.iv && options.salt){
            return new Promise<ParameterReturn>((resolve, reject) => {
                scrypt(password ? password : this.password as string, this.buffer as Buffer, 24, (err: Error | null, key: Buffer): void => {
                    if(err) reject(err);
                    randomFill(new Uint8Array(16), (err: Error | null, iv: Uint8Array) => {
                        if(err) reject(err);
                        this.iv = iv;
                        const cipher = createCipheriv(algorithm ? algorithm : this.algorithm as string, key, iv);

                        const input = createReadStream(path);
                        const output = createWriteStream(`${path}.enc`);

                        pipeline(input, cipher, output, (err: NodeJS.ErrnoException | null) => {
                            if(err) reject(err);
                            resolve({
                                salt: this.buffer as Buffer,
                                iv: this.iv as BinaryLike
                            });;
                        });
                    })
                })
            })
        } else {
            return new Promise<ParameterReturn>((resolve, reject) => {
                this.buffer = randomBytes(16);
                scrypt(password ? password : this.password as string, this.buffer, 24, (err: Error | null, key: Buffer): void => {
                    if(err) reject(err);
                    randomFill(new Uint8Array(16), (err: Error | null, iv: Uint8Array) => {
                        if(err) reject(err);
                        this.iv = iv;
                        const cipher = createCipheriv(algorithm ? algorithm : this.algorithm as string, key, iv);

                        const input = createReadStream(path);
                        const output = createWriteStream(`${path}.enc`);

                        pipeline(input, cipher, output, (err: NodeJS.ErrnoException | null) => {
                            if(err) reject(err);
                            resolve({
                                salt: this.buffer as Buffer,
                                iv: this.iv as BinaryLike
                            });;
                        });
                    })
                })
            })
        }
    };
 
    decrypt = (path: string, algorithm?: string, password?: string, parameters?: Options) => {
        const options = parameters ? parameters as Options : null;
        return new Promise<void>((resolve, reject) => {
            scrypt(password ? password : this.password as string, (options && options.salt) ? options.salt : this.buffer as Buffer, 24, (err: Error | null, key: Buffer): void => {
                if(err) reject(err);
                const input = createReadStream(path);
                const output = createWriteStream("text.txt");
                const decipher = createDecipheriv(algorithm ? algorithm : this.algorithm as string, key, (options && options.iv) ? options.iv : this.iv as BinaryLike);

                pipeline(input, decipher, output, (err: NodeJS.ErrnoException | null) => {
                    if(err) reject(err);
                    resolve();
                })
            })
        })
    };

    encryptSync = (path: string, algorithm?: string, password?: string, parameters?: Options): ParameterReturn | Error => {
        try{
            const options = parameters ? parameters as Options : null;
            if(options && options.salt && options.iv){
                const key = scryptSync(password ? password : this.password as string, options.salt, 24);
                const cipher = createCipheriv(algorithm ? algorithm : this.algorithm as string, key, options.iv);

                const input = createReadStream(path);
                const output = createWriteStream(`${path}.enc`);

                pipeline(input, cipher, output, (err: NodeJS.ErrnoException | null) => {
                    if(err) throw err;
                });
            } else if(options && options.iv && !options.salt){
                this.buffer = randomBytes(16);
                const key = scryptSync(password ? password : this.password as string, this.buffer as Buffer, 24);
                const cipher = createCipheriv(algorithm ? algorithm : this.algorithm as string, key, options.iv);

                const input = createReadStream(path);
                const output = createWriteStream(`${path}.enc`);

                pipeline(input, cipher, output, (err: NodeJS.ErrnoException | null) => {
                    if(err) throw err;
                });
            } else if(options && options.salt && !options.iv){
                const key = scryptSync(password ? password : this.password as string, options.salt, 24);
                randomFill(new Uint8Array(16), (err: Error | null, iv: Uint8Array) => {
                    if(err) throw err;
                    this.iv = iv;
                    const cipher = createCipheriv(algorithm ? algorithm : this.algorithm as string, key, iv);
    
                    const input = createReadStream(path);
                    const output = createWriteStream(`${path}.enc`);
    
                    pipeline(input, cipher, output, (err: NodeJS.ErrnoException | null) => {
                        if(err) throw err;
                    });
                });
            } else {
                this.buffer = randomBytes(16);
                const key = scryptSync(password ? password : this.password as string, this.buffer, 24);
                randomFill(new Uint8Array(16), (err: Error | null, iv: Uint8Array) => {
                    if(err) throw err;
                    this.iv = iv;
                    const cipher = createCipheriv(algorithm ? algorithm : this.algorithm as string, key, iv);

                    const input = createReadStream(path);
                    const output = createWriteStream(`${path}.enc`);

                    pipeline(input, cipher, output, (err: NodeJS.ErrnoException | null) => {
                        if(err) throw err;
                    });
                })
            }
            return {
                salt: this.buffer as Buffer,
                iv: this.iv as BinaryLike
            }
        } catch (err: unknown) {
            return err as Error
        }
    };

    decryptSync = (path: string, algorithm?: string, password?: string, parameters?: Options): void | Error => {
        try{
            const key = scryptSync(password ? password : this.password as string, (parameters && parameters.salt) ? parameters.salt : this.buffer as Buffer, 24);
            
            const input = createReadStream(path);
            const output = createWriteStream("text.txt");
            const decipher = createDecipheriv(algorithm ? algorithm : this.algorithm as string, key, (parameters && parameters.iv) ? parameters.iv : this.iv as BinaryLike);

            pipeline(input, decipher, output, (err: NodeJS.ErrnoException | null) => {
                if(err) throw err;
            })
        } catch (err: unknown){
            return err as Error;
        }
    }
};

export default Encryptor;