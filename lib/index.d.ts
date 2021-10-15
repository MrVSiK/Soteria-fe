/// <reference types="node" />
declare type EncryptionOptions = {
    bytes?: number;
    algorithm?: string;
    iv?: BinaryLike;
    salt?: BinaryLike | Buffer;
    keylen?: number;
    length?: number;
    outputPath?: string;
};
declare type DecryptionOptions = {
    algorithm?: string;
    iv: BinaryLike;
    salt: BinaryLike | Buffer;
    keylen?: number;
    outputPath?: string;
};
declare type Object = {
    salt: BinaryLike | Buffer;
    iv: BinaryLike;
};
export declare type BinaryLike = Uint8Array | Uint8ClampedArray | Uint16Array | Uint32Array | Int8Array | Int16Array | Int32Array | BigUint64Array | BigInt64Array | Float32Array | Float64Array | string;
declare const _default: {
    encrypt: (path: string, password: string, options?: EncryptionOptions | undefined) => Promise<Object>;
    decrypt: (path: string, password: string, options: DecryptionOptions) => Promise<void>;
    encryptSync: (path: string, password: string, options?: EncryptionOptions | undefined) => {
        salt: BinaryLike | Buffer;
        iv: BinaryLike;
    };
    decryptSync: (path: string, password: string, options: DecryptionOptions) => void;
};
export default _default;
//# sourceMappingURL=index.d.ts.map