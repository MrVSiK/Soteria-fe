import assert from 'assert';
import fe from '../src/index';
import { randomFillSync, randomBytes } from 'crypto';
import fs from "fs";

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
    it('Output path specified', () => {
        fe.encrypt(`${__dirname}/test.txt`, '12345678', {
            outputPath: `${__dirname}/happy.enc.txt`
        }).then(() => {
            fs.access(`${__dirname}/happy.enc.txt`,fs.constants.F_OK , (err) => {
                if(err){
                    console.log(err);
                    assert.fail(err);
                }
            });
        }).catch(err => console.log(err));
    });
    it('All parameters', () => {
        const salt = randomBytes(16);
        const iv = randomFillSync(new Uint8Array(16));
        fe.encrypt(`${__dirname}/test.txt`, '12345678', {
            salt: salt,
            iv: iv,
            length: 16,
            bytes: 32,
            outputPath: `${__dirname}/total.enc.txt`,
            algorithm: 'aes-256-cbc',
            keylen: 256/8
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

describe('Sync encryption with different arguments', () => {
    it('No options given', () => {
        const obj = fe.encryptSync(`${__dirname}/test.txt`, '12345678');
        assert.ok(obj);
    });
    it('Bytes, algorithm and keylen', () => {
        const obj = fe.encryptSync(`${__dirname}/test.txt`, '12345678', {
            bytes: 32,
            algorithm: 'aes-256-cbc',
            keylen: 256/8
        });
        assert.equal(obj.salt.length, 32);
    });
    it('bytes, length, iv and salt', () => {
        const salt = randomBytes(16);
        const iv = randomFillSync(new Uint8Array(16));
        const obj = fe.encryptSync(`${__dirname}/test.txt`, '12345678', {
            salt: salt,
            iv: iv,
            length: 16,
            bytes: 16
        });
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
    });
    it('Output path specified', () => {
        const obj = fe.encryptSync(`${__dirname}/test.txt`, '12345678', {
            outputPath: `${__dirname}/happy.enc.txt`
        });
        fs.access(`${__dirname}/happy.enc.txt`,fs.constants.F_OK , (err) => {
            if(err){
                console.log(err);
                assert.fail(err);
            }
        });
    });
    it('All parameters', () => {
        const salt = randomBytes(16);
        const iv = randomFillSync(new Uint8Array(16));
        const obj = fe.encryptSync(`${__dirname}/test.txt`, '12345678', {
            salt: salt,
            iv: iv,
            length: 16,
            bytes: 32,
            outputPath: `${__dirname}/total.enc.txt`,
            algorithm: 'aes-256-cbc',
            keylen: 256/8
        });
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
    });

    it('Clean up', () => {
        setTimeout(() => {
            const arr = ['total.enc.txt','test.enc.txt','happy.enc.txt'];
            for(let i in arr){
                fs.rm(`${__dirname}/${arr[i]}`, (err) => {
                    if(err) assert.fail(err);
                })
            }
        }, 1000);
    })
});