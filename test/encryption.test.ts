import assert from 'assert';
import fe from '../index';
import { randomFillSync, randomBytes } from 'crypto';

describe('Aync encryption with different arguments', () => {
    it('No options given', () => {
        fe.encrypt(`${__dirname}/test.txt`, '12345678').then((obj) => {
            assert.equal('12345678', '12345678');
        }).catch(err => console.log(err));
    });
    it('Bytes, algorithm and keylen', () => {
        fe.encrypt(`${__dirname}/test.txt`, '12345678', {
            bytes: 32,
            algorithm: 'aes-256-cbc',
            keylen: 256/8
        }).then((obj) => {
            assert.equal(obj.salt.length, 32);
        }).catch(err => console.log(err));
    });
    it('bytes, length, iv and salt', () => {
        const salt = randomBytes(16);
        const iv = randomFillSync(new Uint8Array(16));
        fe.encrypt(`${__dirname}/test.txt`, '12345678', {
            salt: salt,
            iv: iv,
            length: 16,
            bytes: 16
        }).then((obj) => {
            assert.deepEqual({
                salt: salt,
                iv: iv,
                length: 16,
                bytes: 16
            }, {
                salt: obj.salt,
                iv: obj.iv,
                length: obj.iv.length,
                bytes: obj.salt.length
            });
        }).catch(err => console.log(err));
    });
});