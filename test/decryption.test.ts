import assert from 'assert';
import fe from '../index';

describe('Async decryption with different parameters', () => {
    it('No options given', () => {
        const p = fe.decrypt(`${__dirname}/test.enc.txt`, '12345678');
        assert.rejects(p, {
            name: 'TypeError'
        })
    });
})