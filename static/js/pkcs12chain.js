import * as asn1js from "asn1js";
import {
  stringToArrayBuffer,
  fromBase64,
} from "pvutils";
import {
  getRandomValues
} from "../node_modules/pkijs/src/common.js";
import Certificate from "../node_modules/pkijs/src/Certificate.js";
import PrivateKeyInfo from "../node_modules/pkijs/src/PrivateKeyInfo";
import Attribute from "../node_modules/pkijs/src/Attribute";
import SafeBag from "../node_modules/pkijs/src/SafeBag";
import PKCS8ShroudedKeyBag from "../node_modules/pkijs/src/PKCS8ShroudedKeyBag";
import PFX from "../node_modules/pkijs/src/PFX";
import AuthenticatedSafe from "../node_modules/pkijs/src/AuthenticatedSafe";
import SafeContents from "../node_modules/pkijs/src/SafeContents";
import CertBag from "../node_modules/pkijs/src/CertBag";

export async function pkcs12chain(priv, certs, password, hash_alg) {
  const asn1 = asn1js.fromBER(stringToArrayBuffer(fromBase64(priv)));
  const pkcs8Simpl = new PrivateKeyInfo({schema: asn1.result});

  const keyLocalIDBuffer = new ArrayBuffer(4);
  const keyLocalIDView = new Uint8Array(keyLocalIDBuffer);
  getRandomValues(keyLocalIDView);

  const bitArray = new ArrayBuffer(1);
  const bitView = new Uint8Array(bitArray);

  bitView[0] = bitView[0] | 0x80;

  const keyUsage = new asn1js.BitString({
      valueHex: bitArray,
      unusedBits: 7
  });

  pkcs8Simpl.attributes = [
      new Attribute({
          type: "2.5.29.15",
          values: [
              keyUsage
          ]
      })
  ];

  const safeBags = [
      new SafeBag({
          bagId: "1.2.840.113549.1.12.10.1.2",
          bagValue: new PKCS8ShroudedKeyBag({
              parsedValue: pkcs8Simpl
          }),
          bagAttributes: [
              new Attribute({
                  type: "1.2.840.113549.1.9.21", // localKeyID
                  values: [
                      new asn1js.OctetString({valueHex: keyLocalIDBuffer})
                  ]
              })
          ]
      })
  ];

  const numCerts = certs.length;
  for (let i=0;i<numCerts;i++) {
    const asn1 = asn1js.fromBER(stringToArrayBuffer(fromBase64(certs[i])));
    const certSimpl = new Certificate({schema: asn1.result});

    const certLocalIDBuffer = new ArrayBuffer(4);
    const certLocalIDView = new Uint8Array(certLocalIDBuffer);
    getRandomValues(certLocalIDView);

    safeBags.push(
      new SafeBag({
        bagId: "1.2.840.113549.1.12.10.1.3",
        bagValue: new CertBag({
            parsedValue: certSimpl
        }),
        bagAttributes: [
          new Attribute({
              type: "1.2.840.113549.1.9.21", // localKeyID
              values: [
                  new asn1js.OctetString({valueHex: certLocalIDBuffer})
              ]
          })
        ]
      })
    );
  }

  let pkcs12 = new PFX({
    parsedValue: {
      integrityMode: 0, // Password-Based Integrity Mode
      authenticatedSafe: new AuthenticatedSafe({
        parsedValue: {
          safeContents: [
            {
              privacyMode: 0, // "No-privacy" Protection Mode
              value: new SafeContents({
                  safeBags: safeBags
              })
            }
          ]
        }
      })
    }
  });

  await pkcs12.parsedValue.authenticatedSafe.makeInternalValues({
    safeContents: [{}]
  });

  await pkcs12.makeInternalValues({
    password: stringToArrayBuffer(password),
    iterations: 10000,
    pbkdf2HashAlgorithm: hash_alg,
    hmacHashAlgorithm: hash_alg
  })

  return pkcs12;
}