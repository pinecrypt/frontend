import * as asn1js from "asn1js";
import {
  arrayBufferToString,
  stringToArrayBuffer,
  toBase64,
  fromBase64,
  bufferToHexCodes
} from "pvutils";
import {
  getCrypto,
  getAlgorithmParameters,
} from "../node_modules/pkijs/src/common.js";
import CertificationRequest from "../node_modules/pkijs/src/CertificationRequest.js";
import AttributeTypeAndValue from "../node_modules/pkijs/src/AttributeTypeAndValue.js";
import Certificate from "../node_modules/pkijs/src/Certificate.js";
import { formatPEM } from "./formatPEM.js";

export async function privKeyToBase64(privKey, crypto) {
  return new Promise(async (resolve, reject) => {
    let arrayBuf = new ArrayBuffer(0);
    arrayBuf = await crypto.exportKey("pkcs8", privKey);
    
    resolve(formatPEM(toBase64(arrayBufferToString(arrayBuf))));
  });
}

export async function privKeyToPem(privKey, crypto) {
  return new Promise(async (resolve, reject) => {
    let privKeyExported = await crypto.exportKey("pkcs8", privKey);
    let privKeyBody = formatPEM(
      toBase64(
        String.fromCharCode.apply(null, new Uint8Array(privKeyExported))
      )
    );
    let privKeyPem = `-----BEGIN RSA PRIVATE KEY-----\r\n${privKeyBody}\r\n-----END RSA PRIVATE KEY-----\r\n`;

    resolve(privKeyPem);
  });
}

export async function certReqToPem(csr) {
  return new Promise(async (resolve, reject) => {
    let resPem = "-----BEGIN CERTIFICATE REQUEST-----\r\n";
    resPem = `${resPem}${formatPEM(
      toBase64(arrayBufferToString(csr.toSchema().toBER(false)))
    )}`;
    resPem = `${resPem}\r\n-----END CERTIFICATE REQUEST-----\r\n`;

    resolve(resPem);
  });
}