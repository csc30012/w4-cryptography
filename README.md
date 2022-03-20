# CSC-30012 - Workshop 4

## Cryptography - Breaking the One-time Pad

This exercise aims at getting a practical understanding of the principles behind (symmetric) cryptography by attempting to break one of the simplest cyphers: the one-time pad.

Note that it is theoretically impossible to break this cypher, as it can be proven that it does achieve perfect secrecy. However, recall that the effectiveness of the cypher relies entirely on the fact that the key is used only once. When the key is shorter than the plain text, it will necessarily be used more than once, thus weakening the cypher.

We’ll simulate a scenario where you are an intruder who has been able to intercept the following message from an encrypted channel that used the one-time pad as encryption method:

```EQYMRwIPKRdJEx8UKRdJFAgCMBwMRx4YNhoMCk0INk4GCQhBMQYIE00INk4ZCBoENwsNRwIHI0A=```

The only additional information you know about it is that it’s been encoded using base64, and that the length of the key used for one-time pad was 6.

Your job is to retrieve the original key and decrypt the message.
