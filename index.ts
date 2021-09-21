import AES from "./src/AES/index";

const aesEncypt = new AES();
aesEncypt.encrypt("test.txt", "aes-192-cbc", "1234").then(() => {
    aesEncypt.decrypt("test.txt.enc", "aes-192-cbc", "1234");
})

export default {
    AES
}