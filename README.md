# AsymCryptJS library

This is a library based on WebCryptoAPI that implements an end-to-end-encrypted communication protocol. Each participant of the communication gets a specific certificate which contains a keypair for encryption/decryption and a keypair for signature/verification of a message.

A participant can start a communication which is a JavaScript-Object that consists of an array of AES-256-encrypted messages and an object that contains the symmetric key which is encrypted with the public key of every participant of this communication.
Every participant can decrypt and verify the messages using his certificate. They can also add encrypted and signed messages to this communication.

## Certificate

A certificate is an object and looks as follows:

```javascript
certificate:
	publicCert:
		keyId
		publicEncryptionKey
		publicVerificationKey
		email
		name:
			firstName
			lastName
	privateCert:
		encrypted:
			public:
				keyId
				publicEncryptionKey
				publicVerificationKey
				email
				name:
					firstName
					lastName
			private:
				privateDecryptionKey
				privateSignatureKey
				fingerprint // of publicCert
				iv // initialization vector for encrypted part of private certificate
```
The encrypted part of privateCert is encrypted with an AES-256 key that is derived from a (hopefully) strong passphrase.

## How to use the library
Just include the file asymcrypt.js in your HTML-file.

### Library functions
1. [createCert](#createcert)
2. [newConversation](#newconversation)
3. [decryptConversation](#decryptconversation)
4. [encryptMessage](#encryptmessage)

#### createCert
Returns a new certificate object.
```javascript
asymcrypt.createCert(
	"first name",
	"last name",
	"example@email.com",
	"passphrase"
)
.then(function(certificate)
{
	console.log(certificate);
})
.catch(function(error)
{
	console.log(error);
});
```

#### newConversation

```javascript
asymcrypt.newConversation(
  "First message of communication",
  certificate, // as created with createCert()
  publicCerts, // an array of public certificates
  "passphrase" // to decrypt privateCert
)
.then(function(conversation)
{
  console.log(conversation);
})
.catch(function(error)
{
  console.log(error);
});
```

Returns a new conversation object:
```javascript
conversation:
	encryptedConversation: // Array of encrypted, b64-encoded messages
  [
    "/OqS/+pkj/tKY…TInoXuS8w==",
    "hzrwWa+f/sEdh…1se5/n5kl8g", …
  ]
  encryptedSymKey: // Object of encrypted symmetric keys labeled with keyId
  {
    7C417E3D: {…},
    F804BFA4: {…}
  }
```

#### decryptConversation

```javascript
asymcrypt.decryptConversation(
  conversation, // as created with newConversation()
  certificate, // as created with createCert()
  "passphrase", // to decrypt privateCert
  publicCerts, // an array of public certificates to verify message signatures
)
.then(function(decrypted))
{
  console.log(decrypted);
})
.catch(function(error)
{
  console.log(error);
});
```

Returns an array of decrypted and verified messages of a communication:
```javascript
[
  {
    content:
    {
      content: "First message of communication"
      signatureKeyId: "F804BFA4"
    }
    verified: true
  }
  {
    content:
    {
      content: "Content of the message"
      signatureKeyId: "7C417E3D"
    }
    verified: true
  }
]
```


#### encryptMessage

```javascript
asymcrypt.encryptMessage(
  "Content of the message",
  encryptedSymKeys, // from existing communication
  certificate, // as created with createCert()
  "passphrase" // to decrypt privateCert
)
.then(function(message)
{
  console.log(message);
})
.catch(function(error)
{
  console.log(error);
});
```

Returns an encrypted b64-encroded message which can be added to a conversation.
```javascript
"WPkCQIe7sYruGG+…/e7sYruG7L"
```
