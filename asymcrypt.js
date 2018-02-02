/*

######################## Library AsymCryptJS ########################

Written by Moritz Jordan
License: GNU General Public License v3.0
Usage: Please view the README.md
https://github.com/moritzjordan/AsymCryptJS

#####################################################################

*/


(function(window)
{
  'use strict';

  function asymcrypt()
  {
    var _asymcryptObject = {};

    // Private properties
    var keySize = 4096;

    // Private functions

    // Transforms a string into a Uint8Array
    var stringToUint8Array = function (str)
    {
      var bytes = new Uint8Array(str.length);
      for (var i = 0; i < str.length; i++)
      {
        bytes[i] = str.charCodeAt(i);
      }
      return bytes;
    }

    // Transforms a Uint8Array into a string
    var Uint8ArrayToString = function (buf)
    {
      var str = "";
      for (var i = 0; i < buf.byteLength; i++)
      {
        str += String.fromCharCode(buf[i]);
      }
      return str;
    }

    // Transforms an integer into a hexadecimal
		// only works with 0 <= x < 256 integers
    var decToHex = function (dec)
    {
      var firstDigit = Math.floor(dec / 16);
      var secondDigit = dec % 16;
      if (firstDigit >= 1)
      {
        switch (firstDigit)
        {
          case 10: firstDigit = "A"; break;
          case 11: firstDigit = "B"; break;
          case 12: firstDigit = "C"; break;
          case 13: firstDigit = "D"; break;
          case 14: firstDigit = "E"; break;
          case 15: firstDigit = "F"; break;
          default: firstDigit = firstDigit.toString();
        }
      } else {
        firstDigit = "0";
      }
      switch (secondDigit)
      {
        case 10: secondDigit = "A"; break;
        case 11: secondDigit = "B"; break;
        case 12: secondDigit = "C"; break;
        case 13: secondDigit = "D"; break;
        case 14: secondDigit = "E"; break;
        case 15: secondDigit = "F"; break;
        default: secondDigit = secondDigit.toString();
      }
      return firstDigit + secondDigit;
    }

    // Transforms a Uint8Array to a hexadecimal string
    var Uint8ArrayToHexString = function (buf)
    {
      var str = "";
      for (var i = 0; i < buf.byteLength; i++)
      {
        str += decToHex(buf[i]);
      }
      return str;
    }

    // Derives a 256Bit AES-Key from a passphrase given as a string
    var makeKeyObjectFromPassphrase = function (passphrase)
    {
      return new Promise(function (resolve, reject)
      {
        var sequence = Promise.resolve();

        sequence = sequence.then(
          function ()
          {
            // create encryption keypair
            return crypto.subtle.digest(
              {name: "SHA-256",},
              stringToUint8Array(passphrase)
            );
          }
        );
        sequence = sequence.then(
          function (hash)
          {
            return crypto.subtle.importKey(
              "raw",
              new Uint8Array(hash),
              {name: "AES-CBC"},
              false,
              ["encrypt", "decrypt"]
            );
          },
          function (error)
          {
            reject("Error during hashing passphrase: " + error);
          }
        );
        sequence = sequence.then(
          function (keyObject)
          {
            resolve(keyObject);
          },
          function (error)
          {
            reject("Error during key import from hashed passphrase: " + error);
          }
        );
      });
    }

    // Creates a key as a JSON string
    var createKeyJSON = function (algorithm, keyUsages)
    {
      return new Promise (function (resolve, reject)
      {
        var keyObject = {};
        var keyJSON = {};

        var sequence = Promise.resolve();

        sequence = sequence.then(
          function ()
          {
            //return newKey(algorithm, keyUsages);
            return crypto.subtle.generateKey(
              {
                name: algorithm, //
                modulusLength: keySize, // can be 1024, 2048, or 4096
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: {name: "SHA-256"}, // can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
              },
              true, // whether the key is extractable
              keyUsages
            );
          }
        );
        sequence = sequence.then(
          function (key)
          {
            keyObject = key;
            return crypto.subtle.exportKey("spki", keyObject.publicKey);
          },
          function (error)
          {
            reject("Error during " + algorithm + " key generation: " + error);
          }
        );
        sequence = sequence.then(
          function (keyData)
          {
            keyJSON.publicKey = "-----BEGIN PUBLIC KEY-----"
              + btoa(Uint8ArrayToString(new Uint8Array(keyData)))
              + "-----END PUBLIC KEY-----";
            return crypto.subtle.exportKey("jwk", keyObject.privateKey);
          },
          function (error)
          {
            reject("Error during " + algorithm + " key export of public Key: " + error);
          }
        );
        sequence = sequence.then(
          function(keyData)
          {
            keyJSON.privateKey = keyData;
            resolve(keyJSON);
          },
          function (error)
          {
            reject("Error during " + algorithm + " key export of private Key: " + error);
          }
        );
      });
    }

		// decrypts a private certificate given the corresponding passphrase
    var decryptPrivateCert = function (privateCert, passphrase)
    {
      return new Promise(function (resolve, reject)
      {
        var sequence = Promise.resolve();
        sequence = sequence.then(
          function()
          {
            return makeKeyObjectFromPassphrase(passphrase);
          }
        );
        sequence = sequence.then(
          function(keyObject)
          {
            return crypto.subtle.decrypt(
              {
                name: "AES-CBC",
                iv: stringToUint8Array(atob(privateCert.iv))
              },
              keyObject,
              stringToUint8Array(atob(privateCert.encrypted))
            );
          },
          function(error)
          {
            reject(error);
          }
        );
        sequence = sequence.then(
          function(decrypted)
          {
            resolve(JSON.parse(Uint8ArrayToString(new Uint8Array(decrypted))));
          },
          function(error)
          {
            reject("Error during decryption of private certificate: " + error);
          }
        );
      });
    }

		// encrypts a key with every public certificate given as an array
    // adds encrypted symmetric key to encryptedSymKeys object
    var encryptKeyJSON = function (key, publicKeys, encryptedSymKeys)
    {
      return new Promise(function (resolve, reject)
      {
        key = stringToUint8Array(key);

        var i = 0;
        while(publicKeys[i])
        {
          (function (i)
          {
            var sequence = Promise.resolve();
            var iv;

            sequence = sequence.then(
              function()
              {
                var publicEncryptionKey = publicKeys[i].publicEncryptionKey;
                publicEncryptionKey = publicEncryptionKey.replace("-----BEGIN PUBLIC KEY-----", "");
                publicEncryptionKey = publicEncryptionKey.replace("-----END PUBLIC KEY-----", "");
                publicEncryptionKey = stringToUint8Array(atob(publicEncryptionKey));
                return crypto.subtle.importKey(
                  "spki",
                  publicEncryptionKey,
                  {
                    name: "RSA-OAEP",
                    hash: {name: "SHA-256"}
                  },
                  false,
                  ['encrypt']
                );
              }
            );
            sequence = sequence.then(
              function(publicKeyObject)
              {
                var vector = crypto.getRandomValues(new Uint8Array(16));
                iv = btoa(Uint8ArrayToString(vector));
                return window.crypto.subtle.encrypt(
                  {
                    name: "RSA-OAEP",
                    iv: vector
                  },
                  publicKeyObject,
                  key
                );
              },
              function(error)
              {
                reject("Error during import of public encryption key (id: " + publicKeys[i].keyId + "): " + error);
              }
            );
            sequence = sequence.then(
              function(encryptedSymKey)
              {
                encryptedSymKeys[publicKeys[i].keyId] =
                {
                  encryptedSymKey: btoa(Uint8ArrayToString(new Uint8Array(encryptedSymKey))),
                  iv: iv
                };
                if (i == publicKeys.length - 1)
                {
                  resolve(encryptedSymKeys);
                }
              },
              function(error)
              {
                reject("Error during encryption of symmetric key with public key (id: " + publicKeys[i].keyId + "): " + error);
              }
            );
          })(i);
          i++;
        }
      });
    }

		// signs and encrypts a message given as a string
		// needs a private certificate, the symmetric key given as an object
		// and the initialization vector corresponding to the communication
    var signEncryptMessage = function(message, privateCert, symKeyObject, iv)
    {
      return new Promise(function(resolve, reject)
      {
        var sequence = Promise.resolve();

        var signedMessage =
        {
          signature: "",
          message: {
            content: message,
            signatureKeyId: ""
          }
        };
        var privateKeyObject;

        sequence = sequence.then(
          function()
          {
            return crypto.subtle.importKey(
              "jwk",
              privateCert.private.privateSignatureKey,
              {
                name: "RSASSA-PKCS1-v1_5",
                hash: {name: "SHA-256"}
              },
              false,
              ['sign']
            );
          },
          function(error)
          {
            reject(error);
          }
        );
        sequence = sequence.then(
          function(imported)
          {
            privateKeyObject = imported;
            return crypto.subtle.digest(
              {name: "SHA-256",},
              stringToUint8Array(signedMessage.message)
            );
          },
          function(error)
          {
            reject("Error during import of private signature key: " + error);
          }
        );
        sequence = sequence.then(
          function(hash)
          {
            return crypto.subtle.sign(
              {
                name: "RSASSA-PKCS1-v1_5",
              },
              privateKeyObject,
              new Uint8Array(hash)
            )
          },
          function(error)
          {
            reject("Error during creating hash of message:  " + error);
          }
        );
        sequence = sequence.then(
          function(signature)
          {
            signedMessage.signature = btoa(Uint8ArrayToString(new Uint8Array(signature)));
            signedMessage.message.signatureKeyId = privateCert.public.keyId;
            return crypto.subtle.encrypt(
              {
                name: "AES-CBC",
                iv: iv,
              },
              symKeyObject,
              stringToUint8Array(JSON.stringify(signedMessage))
            );
          },
          function(error)
          {
            reject("Error during signing message: " + error);
          }
        );
        sequence = sequence.then(
          function(encrypted)
          {
            resolve(btoa(Uint8ArrayToString(new Uint8Array(encrypted))));
          },
          function(error)
          {
            reject("Error during encryption of message: " + error);
          }
        );
      });
    }

		// extracts the symmetric key of a communication given
		// the object containig the encrypted symmetric keys
		// and the private certificate to decrypt the key
    var extractSymKeyObject = function(privateCert, symKeys)
    {
      return new Promise(function(resolve, reject)
      {

        var iv;
        var sequence = Promise.resolve();

        sequence = sequence.then(
          function()
          {
            return crypto.subtle.importKey(
              "jwk",
              privateCert.private.privateDecryptionKey,
              {
                name: "RSA-OAEP",
                hash: {name: "SHA-256"}
              },
              false,
              ['decrypt']
            );
          }
        );
        sequence = sequence.then(
          function(privateDecryptionKey)
          {
            var encryptedSymKey = symKeys[privateCert.public.keyId];

            return window.crypto.subtle.decrypt(
              {
                name: "RSA-OAEP",
                iv: stringToUint8Array(atob(encryptedSymKey.iv))
              },
              privateDecryptionKey,
              stringToUint8Array(atob(encryptedSymKey.encryptedSymKey))
            );
          },
          function(error)
          {
            reject("Error during import of private decryption key: " + error);
          }
        );
        sequence = sequence.then(
          function(decryptedSymKey)
          {
            var decryptedSymKeyJSON = JSON.parse(Uint8ArrayToString(new Uint8Array(decryptedSymKey)));
            iv = stringToUint8Array(atob(decryptedSymKeyJSON.iv));

            return window.crypto.subtle.importKey(
              "jwk",
              decryptedSymKeyJSON.key,
              {
                name: "AES-CBC",
              },
              false,
              ["encrypt", "decrypt"]
            );
          },
          function(error)
          {
            reject("Error during decryption of symmetric key: " + error);
          }
        );
        sequence = sequence.then(
          function(symKeyObject)
          {
            resolve(
              {
                key: symKeyObject,
                iv: iv
              }
            );
          },
          function(error)
          {
            reject("Error during import of symmetric key: " + error);
          }
        );
      });
    }

		// verifies a message given the message as a String
		// and the public certificate that was used to sign the message
    var verifyMessage = function(message, publicCert)
    {
      return new Promise(function(resolve, reject)
      {
        var sequence = Promise.resolve();
        var publicVerificationKeyObject;

        sequence = sequence.then(
          function()
          {
            var publicVerificationKey = publicCert.publicVerificationKey;
            publicVerificationKey = publicVerificationKey.replace("-----BEGIN PUBLIC KEY-----", "");
            publicVerificationKey = publicVerificationKey.replace("-----END PUBLIC KEY-----", "");
            publicVerificationKey = stringToUint8Array(atob(publicVerificationKey));
            return window.crypto.subtle.importKey(
              "spki",
              publicVerificationKey,
              {
                name: "RSASSA-PKCS1-v1_5",
                hash: {name: "SHA-256"},
              },
              false,
              ["verify"]
            );
          }
        );
        sequence = sequence.then(
          function(keyObject)
          {
            publicVerificationKeyObject = keyObject;
            return crypto.subtle.digest(
              {name: "SHA-256",},
              stringToUint8Array(message.message)
            );
          },
          function(error)
          {
            reject("Error during import of public verification key (id: " + publicCert.keyId + "): " + error);
          }
        );
        sequence = sequence.then(
          function(hash)
          {
            return window.crypto.subtle.verify(
              {
                name: "RSASSA-PKCS1-v1_5",
              },
              publicVerificationKeyObject,
              stringToUint8Array(atob(message.signature)),
              new Uint8Array(hash)
            );
          },
          function(error)
          {
            reject("Error during hashing the message: " + error);
          }
        );
        sequence = sequence.then(
          function(isValid)
          {
            resolve(isValid);
          },
          function(error)
          {
            reject("Error during message verification: " + error);
          }
        );
      });
    }

		// returns a public key from an array of public keys given the specific keyId
    var getPublicKey = function(keyId, publicKeys)
    {
      var i = 0;
      while(publicKeys[i])
      {
        if (publicKeys[i].keyId == keyId)
        {
          return publicKeys[i];
        }
        i++;
      }
      return undefined;
    }

    // Public functions

    // creates a certificate
    _asymcryptObject.createCert = function (firstName, lastName, email, passphrase)
    {
      return new Promise(function (resolve, reject)
      {
				// declare variables
        var certificate = {
          publicCert: {
            keyId: "",
            publicEncryptionKey: {},
            publicVerificationKey: {},
            email: email,
            name: {
              firstName,
              lastName
            },
          },
          privateCert: {
            encrypted: "",
            iv: ""
          }
        };
        var encryptedPart = {
          public: {
            keyId: "",
            publicEncryptionKey: {},
            publicVerificationKey: {},
            email: email,
            name: {
              firstName,
              lastName
            },
          },
          private: {
            privateDecryptionKey: {},
            privateSignatureKey: {}
          },
          fingerprint: ""
        };
        var iv;

        var sequence = Promise.resolve();

        sequence = sequence.then(
          function ()
          {
            // create encryption keypair
            return createKeyJSON("RSA-OAEP", ["encrypt", "decrypt"]);
          }
        );
        sequence = sequence.then(
          function(key)
          {
            certificate.publicCert.publicEncryptionKey = key.publicKey;
            encryptedPart.private.privateDecryptionKey = key.privateKey;
            encryptedPart.public.publicEncryptionKey = key.publicKey;
						// create signature keypair
            return createKeyJSON("RSASSA-PKCS1-v1_5", ["sign", "verify"]);
          },
          function (error)
          {
            reject(error);
          }
        );
        sequence = sequence.then(
          function(key)
          {
            certificate.publicCert.publicVerificationKey = key.publicKey;
            encryptedPart.private.privateSignatureKey = key.privateKey;
            encryptedPart.public.publicVerificationKey = key.publicKey;
						// create fingerprint for public certificate
            return crypto.subtle.digest(
              {name: "SHA-1"},
              stringToUint8Array(JSON.stringify(certificate.publicCert))
            );
          },
          function (error)
          {
            reject(error);
          }
        );
        sequence = sequence.then(
          function(hash)
          {
            var fingerprint = Uint8ArrayToHexString(new Uint8Array(hash));
            encryptedPart.fingerprint = fingerprint;
            certificate.publicCert.keyId = fingerprint.substr(32);
            encryptedPart.public.keyId = fingerprint.substr(32);
						// create symmetric key for private certificate encryption
            return makeKeyObjectFromPassphrase(passphrase);
          },
          function (error)
          {
            reject("Error during creation of fingerprint for public key: " + error);
          }
        );
        sequence = sequence.then(
          function(keyObject)
          {
            iv = crypto.getRandomValues(new Uint8Array(16));
						// encrypt private certificate
            return crypto.subtle.encrypt(
              {
                name: "AES-CBC",
                iv: iv,
              },
              keyObject,
              stringToUint8Array(JSON.stringify(encryptedPart))
            );
          },
          function(error)
          {
            reject(error);
          }
        );
        sequence = sequence.then(
          function(encrypted)
          {
            certificate.privateCert.encrypted = btoa(Uint8ArrayToString(new Uint8Array(encrypted)));
            certificate.privateCert.iv = btoa(Uint8ArrayToString(iv));
						// return certificate
            resolve(certificate);
          },
          function (error)
          {
            reject("Error during encryption of private key with passphrase: " + error);
          }
        );
      });
    }

    // creates a new conversation with first message and encrypted symmetric key
    _asymcryptObject.newConversation = function (message, certificate, publicKeys, passphrase)
    {
      return new Promise(function (resolve, reject)
      {
				// declare variables
        var signedMessage =
        {
          signature: "",
          message: {
            content: message,
            signatureKeyId: ""
          }
        };
        var privateCert;
        var privateKeyObject;
        var symKeyObject;
        var iv = crypto.getRandomValues(new Uint8Array(16));
        var encryptedMessage;
        var symKeyJSON =
        {
          iv: btoa(Uint8ArrayToString(iv)),
          key: ""
        }
        var encryptedSymKeys = [];
        var allPublicKeys = publicKeys.slice();

        var sequence = Promise.resolve();

        sequence = sequence.then(
          function()
          {
						// create symmetric communication key
            return crypto.subtle.generateKey(
              {
                name: "AES-CBC",
                length: 256,
              },
              true,
              ["encrypt", "decrypt"]
            );
          }
        );
        sequence = sequence.then(
          function(symKeyObj)
          {
            symKeyObject = symKeyObj;
						// decrypt private certificate
            return decryptPrivateCert(certificate.privateCert, passphrase);
          },
          function(error)
          {
            reject("Error during generation of symmetric message key" + error);
          }
        );
        sequence = sequence.then(
          function(decrypted)
          {
            privateCert = decrypted;
						// sign and encrypt message given the private certificate
            return signEncryptMessage(message, privateCert, symKeyObject, iv);
          },
          function(error)
          {
            reject(error);
          }
        );
        sequence = sequence.then(
          function(encrypted)
          {
            encryptedMessage = encrypted;
						// export the symmetric communication key
            return crypto.subtle.exportKey("jwk", symKeyObject);
          },
          function(error)
          {
            reject(error);
          }
        );
        sequence = sequence.then(
          function(keyJSON)
          {
            symKeyJSON.key = keyJSON;
            symKeyJSON = JSON.stringify(symKeyJSON);
            allPublicKeys.push(privateCert.public);
						// encrypt the symmetric communication key with all given public keys
            var encryptedSymKeys = {};
            return encryptKeyJSON(symKeyJSON, allPublicKeys, encryptedSymKeys);
          },
          function(error)
          {
            reject("Error during export of symmetric message key: " + error);
          }
        );
        sequence = sequence.then(
          function(encryptedSymKeys)
          {
						// return the communication object
            resolve(
              {
                encryptedConversation: [encryptedMessage],
                encryptedSymKeys: encryptedSymKeys
              }
            );
          },
          function(error)
          {
            reject(error);
          }
        );
      });
    }

		// encrypts a message given the symmetric communication key
    _asymcryptObject.encryptMessage = function (message, symKeys, certificate, passphrase)
    {
      return new Promise(function (resolve, reject)
      {
				// declare variables
        var privateCert;

        var sequence = Promise.resolve();

        sequence = sequence.then(
          function()
          {
						// decrypt the private certificate
            return decryptPrivateCert(certificate.privateCert, passphrase);
          }
        );
        sequence = sequence.then(
          function(decrypted)
          {
            privateCert = decrypted;
						// extract the symmetric communication key object from the symKeys-object
            return extractSymKeyObject(privateCert, symKeys);
          },
          function(error)
          {
            reject(error);
          }
        );
        sequence = sequence.then(
          function(symKeyObject)
          {
						// sign and encrypt the new message
            return signEncryptMessage(message, privateCert, symKeyObject.key, symKeyObject.iv);
          },
          function(error)
          {
            reject(error);
          }
        );
        sequence = sequence.then(
          function(encrypted)
          {
						// return the encrypted message
            resolve(encrypted);
          }
        );
      });
    }

		// decrypt a conversation
    _asymcryptObject.decryptConversation = function (conversation, certificate, passphrase, publicKeys)
    {
      return new Promise(function (resolve, reject)
      {
				// declare variables
        var privateCert;

        var sequence = Promise.resolve();

        sequence = sequence.then(
          function()
          {
						// decrypt private certificate
            return decryptPrivateCert(certificate.privateCert, passphrase);
          }
        );
        sequence = sequence.then(
          function(decrypted)
          {
            privateCert = decrypted;
						// extract symmetric communication key
            return extractSymKeyObject(privateCert, conversation.encryptedSymKeys);
          },
          function(error)
          {
            reject(error);
          }
        );
        sequence = sequence.then(
          function(symKeyObject)
          {
            var verifiedMessages = [];

            var i = 0;
						// loop over the array of encrypted messages
            while(conversation.encryptedConversation[i])
            {
							// anonymous function for loop of asynchronous functions
							// to create an individual scope for each loop pass
              (function(i){

                var sequence = Promise.resolve();
                var decryptedMessage;

                sequence = sequence.then(
                  function()
                  {
										// decrypt the encrypted message
                    return window.crypto.subtle.decrypt(
                      {
                        name: "AES-CBC",
                        iv: symKeyObject.iv
                      },
                      symKeyObject.key,
                      stringToUint8Array(atob(conversation.encryptedConversation[i]))
                    );
                  }
                );
                sequence = sequence.then(
                  function(decrypted)
                  {
                    decryptedMessage = JSON.parse(Uint8ArrayToString(new Uint8Array(decrypted)));
										// get the public verification key for specific message
                    var messageOwnersKey = getPublicKey(decryptedMessage.message.signatureKeyId, publicKeys);
                    if (messageOwnersKey)
                    {
											// verify the message
                      return verifyMessage(decryptedMessage, messageOwnersKey);
                    } else {
                      return "No public verification key found.";
                    }
                  },
                  function(error)
                  {
                    reject("Error during decryption of message: " + error);
                  }
                );
                sequence = sequence.then(
                  function(isValid)
                  {
										// add verified message to result-array
                    verifiedMessages.push(
                      {
                        content: decryptedMessage.message,
                        verified: isValid
                      }
                    );
                    if (i == conversation.encryptedConversation.length - 1)
                    {
                      resolve(verifiedMessages);
                    }
                  },
                  function(error)
                  {
										// add non-verified message to result-array
                    verifiedMessages.push(
                      {
                        content: decryptedMessage.message,
                        verified: "Error during message verification."
                      }
                    );
                    if (i == conversation.encryptedConversation.length - 1)
                    {
											// return array of decrypted/verified messages
                      resolve(verifiedMessages);
                    }
                  }
                );
              })(i);
              i++;
            }
          },
          function(error)
          {
            reject(error);
          }
        );
      });
    }

    /*
    _asymcryptObject.addUserToConversation = function(conversation, certificate, publicKeys)
    {
      return new Promise(function(resolve, reject)
      {
        var sequence = Promise.resolve();
        var privateCert;

        sequence = sequence.then(
          function()
          {
            return decryptPrivateCert(certificate.privateCert, passphrase);
          }
        );
        sequence = sequence.then(
          function(decrypted)
          {
            privateCert = decrypted;
						// extract symmetric communication key
            return extractSymKeyObject(privateCert, conversation.encryptedSymKeys);
          },
          function(error)
          {
            reject(error);
          }
        );
        sequence = sequence.then(
          function(symKeyObject)
          {

          }
        );
      });
    }
    */

    return _asymcryptObject;
  }

  // Make library 'asymcrypt' globally accessible
  if(typeof(window.asymcrypt) === 'undefined'){
    window.asymcrypt = asymcrypt();
  }
})(window);
