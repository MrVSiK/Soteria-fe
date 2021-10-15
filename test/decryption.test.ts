import assert from "assert";
import fe from "../src/index";
import fs from "fs";
import { randomFillSync, randomBytes } from "crypto";

describe("Async decryption with different parameters", () => {
  it("Salt, iv and outputPath", () => {
    fe.encrypt(`${__dirname}/test.txt`, "12345678", {
      outputPath: `${__dirname}/test1.enc.txt`,
    })
      .then(({ salt, iv }) => {
        fe.decrypt(`${__dirname}/test1.enc.txt`, "12345678", {
          salt: salt,
          iv: iv,
          outputPath: `${__dirname}/test1.txt`,
        })
          .then(() => {
            fs.readFile(`${__dirname}/test.txt`, "utf8", (err, data) => {
              if (err) assert.fail(err);
              fs.readFile(`${__dirname}/test1.txt`, "utf8", (err, data1) => {
                if (err) assert.fail(err);
                assert.equal(data1, data);
              });
            });
          })
          .catch((err) => {
            console.log(err);
            assert.fail(err);
          });
      })
      .catch((err) => {
        console.log(err);
        assert.fail(err);
      });
  });

  it("All parameters", () => {
    const salt = randomBytes(16);
    const iv = randomFillSync(new Uint8Array(16));
    fe.encrypt(`${__dirname}/test.txt`, "12345678", {
      salt: salt,
      iv: iv,
      length: 16,
      bytes: 32,
      outputPath: `${__dirname}/test2.enc.txt`,
      algorithm: "aes-256-cbc",
      keylen: 256 / 8,
    })
      .then(() => {
        fe.decrypt(`${__dirname}/test2.enc.txt`, "12345678", {
          salt: salt,
          iv: iv,
          outputPath: `${__dirname}/test2.txt`,
          algorithm: "aes-256-cbc",
          keylen: 256 / 8,
        })
          .then(() => {
            fs.readFile(`${__dirname}/test.txt`, "utf8", (err, data) => {
              if (err) assert.fail(err);
              fs.readFile(`${__dirname}/test2.txt`, "utf8", (err, data1) => {
                if (err) assert.fail(err);
                assert.equal(data1, data);
              });
            });
          })
          .catch((err) => {
            console.log(err);
            assert.fail(err);
          });
      })
      .catch((err) => {
        console.log(err);
        assert.fail(err);
      });
  });
});

describe("Sync descryption with different parameters", () => {
  it("Salt, iv and output path", () => {
    try {
      fe.encrypt(`${__dirname}/test.txt`, "12345678", {
        outputPath: `${__dirname}/test3.enc.txt`,
      }).then(({ salt, iv }) => {
        fe.decryptSync(`${__dirname}/test3.enc.txt`, "12345678", {
          salt: salt,
          iv: iv,
          outputPath: `${__dirname}/test3.txt`,
        });
        fs.readFile(`${__dirname}/test.txt`, "utf8", (err, data) => {
          if (err) assert.fail(err);
          fs.readFile(`${__dirname}/test3.txt`, "utf8", (err, data1) => {
            if (err) assert.fail(err);
            assert.equal(data1, data);
          });
        });
      });
    } catch (err) {
      console.log(err);
      assert.fail(err as Error);
    }
  });
  it("All parameters", () => {
    try {
      const salt = randomBytes(16);
      const iv = randomFillSync(new Uint8Array(16));
      fe.encrypt(`${__dirname}/test.txt`, "12345678", {
        salt: salt,
        iv: iv,
        length: 16,
        bytes: 32,
        outputPath: `${__dirname}/test4.enc.txt`,
        algorithm: "aes-256-cbc",
        keylen: 256 / 8,
      }).then(() => {
        fe.decryptSync(`${__dirname}/test4.enc.txt`, "12345678", {
          salt: salt,
          iv: iv,
          algorithm: "aes-256-cbc",
          keylen: 256 / 8,
        });
      });
    } catch (err) {
      console.log(err);
      assert.fail(err as Error);
    }
  });

  it('Clean up', () => {
    setTimeout(() => {
        const arr = ['test1.enc.txt','test2.enc.txt','test3.enc.txt','test4.enc.txt','test1.txt','test2.txt','test3.txt','test4.txt'];
        for(let i in arr){
            fs.rm(`${__dirname}/${arr[i]}`, (err) => {
                if(err) assert.fail(err);
            })
        }
    }, 1000);
  })
});
