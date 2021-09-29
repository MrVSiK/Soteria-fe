import assert from "assert";
import fe from "../src/files/index";

describe("Test encryption with file", () => {
    it("Should encrypt the file", () => {
        const aes = new fe();
        aes.encrypt("../test.txt", "aes-192-cbc", "12345678").then(({salt, iv}) => {
            assert.equal(salt, aes.buffer);
            assert.equal(iv, aes.iv);
            assert.equal("aes-192-cbc", aes.algorithm);
        })
    })
})