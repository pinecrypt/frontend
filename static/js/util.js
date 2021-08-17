import {
  arrayBufferToString,
  toBase64,
} from "pvutils";
import { formatPEM } from "./formatPEM.js";

export function pkijsToBase64(pkijsObj) {
  return new Promise(async (resolve, reject) => {
    switch(pkijsObj.__proto__.constructor.name) {
      case "CryptoKey":
        let arrayBuf = new ArrayBuffer(0);

        if (pkijsObj.type == "private")
          arrayBuf = await window.cryptoEngine.exportKey("pkcs8", pkijsObj);
        else
          arrayBuf = await window.cryptoEngine.exportKey("spki", pkijsObj);
        
        resolve(toBase64(arrayBufferToString(arrayBuf)));
        break;

      case "CertificationRequest":
        resolve(toBase64(arrayBufferToString(pkijsObj.toSchema().toBER(false))));
        break;
    }
  });
}

export function pkijsToPem(pkijsObj) {
  return new Promise(async (resolve, reject) => {
    switch(pkijsObj.__proto__.constructor.name) {
      case "CryptoKey":
        let privKeyExported = await window.cryptoEngine.exportKey("pkcs8", pkijsObj);
        let privKeyBody = formatPEM(
          toBase64(
            String.fromCharCode.apply(null, new Uint8Array(privKeyExported))
          )
        );
        resolve(`-----BEGIN PRIVATE KEY-----\r\n${privKeyBody}\r\n-----END PRIVATE KEY-----\r\n`);
        break;

      case "CertificationRequest":
        let resPem = "-----BEGIN CERTIFICATE REQUEST-----\r\n";
        resPem = `${resPem}${formatPEM(
          toBase64(arrayBufferToString(pkijsObj.toSchema().toBER(false)))
        )}`;
        resolve(`${resPem}\r\n-----END CERTIFICATE REQUEST-----\r\n`);
        break;
      }
  });
}