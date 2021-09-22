import Algo from "./src/files/index";

const aes = new Algo()
aes.encrypt("test.txt", "aes-192-cbc", "12345").then(() => {
    aes.decrypt("test.txt.enc", "aes-192-cbc", "12345").catch((err) => console.log(err))
}).catch((err) => console.log(err))



export default {
    Algo
}