# Trendmicro 2018: Analysis Offensive 400

__Tags:__ `crypto`, `aes`  
__Total Points:__ 400

## Problem Statement

ACME Corp rolled their own stateless, sockets-based protocol for authenticating and issuing remote commands to a server. They soon realized that their protocol has poor MITM resistance, so they decided to run it over TLS. But there is another major flaw, and it lets any attacker get admin on the server! Find the flaw and code a malicious client.

To keep things simple, we'll run the protocol over TCP with no TLS, but you should assume that you don't have a way to eavesdrop or MITM a conversation between the server and a legitimate user. Also assume the configured passwords are strong enough to withstand brute force attack.

The challenge consists of these files:

* ACME_Protocol.docx : Full protocol specification
* refClient.py : A reference implementation of the client part of the protocol
* refServer.py : A reference implementation of the server part of the protocol
* challengeServer.py : The real server you will need to point your attack at to get the flag. Most of the protocol is implemented within a heavily obfuscated x86 ELF binary named server.

__Note:__ It was enough for me to read the *ACME_Protocol.docx* to figure out the major flaw and how to exploit it. Take time to read the ACME Protocol first before you read the solution. I enjoyed solving this.

## Solution

### Analyze the Protocol

The protocol can be summarized in the following steps (where `|` is concatenate):

1. To log on, the client first sends the __username__.
2. The server responds with a challenge 8-byte nonce and an encrypted challenge cookie. <br> `AES.encrypt(nonce | username | timestamp )`.
3. The client authenticates by answering the challenge using knowledge of the password. The client passes the answer together with the  challenge cookie back to the server.
4. The server issues a session ticket, <br> `AES.encrypt(identity | timestamp)`.
5. The client presents this ticket to establish its identity whenever issuing a command. To log off, the client simply discards the ticket.

The protocol uses a cookie/ticket that is encrypted using __AES CBC__, which contains all the information used to validate a logon request or to authenticate for a command. Both the challenge cookie and the session ticket use the same key.

A sample of the __identity__ is `{"user": "admin", "groups": ["admin"]}`

#### Easier Form of the Problem

Let's say that the challenge cookie _does not have a nonce_, then challenge cookie comes in the form `AES.encrypt(username | timestamp)`.

If we can use the username `{"user": "admin", "groups": ["admin"]}` so that __our challenge cookie becomes a valid session ticket.__

#### Solving the Original Problem

We need to find a way to remove the __nonce__ in the challenge cookie to be able to create valid session tickets.

Let's look at how __AES CBC__ works,

![AES CBC](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/902px-CBC_decryption.svg.png)

Notice that the __IV__ is only used on the first block the of ciphertext, and __the first block of ciphertext is used as the IV of the the second block.__ So given a pair `(IV, C)`, you can construct another pair `(C[:16]',C[16:]')` that will be properly decrypted by the server, but the resultant plaintext will not have the first 16 bytes of the original plaintext.

__With this we can remove the nonce! We just pad our input by 8 bytes so that the first 16 bytes is just the ( nonce | padding )__

Here is a pseudocode to explain
```python
iv, c = AES.encrypt(key, (nonce | padding | identity | timestamp)) # (nonce | padding) should be exactly 16 bytes
iv, c = c[:16], c[16:]
plaintext = AES.decrypt(key, iv, c)
assert plaintext == (identity | timestamp)
```

#### Exploit

So our exploit would be:
1. To log on, the client first sends the __(padding | identity)__.
2. The server responds the encrypted challenge cookie. <br> `AES.encrypt(nonce | padding | username | timestamp )`.
3. The client uses the encrypted challenge cookie to create a valid session cookie..
4. The server issues a session ticket, <br> `AES.encrypt(identity | timestamp)`.
5. The client presents this ticket to establish its identity and get the flag.

With that we can get the flag!  
`# TMCTF{90F41EF71ED5}`

## Implementing a malicious client

We modify the `refClient.py` to do this.

### Original refClient
```python
# Abridged version of client
class Client:
	def __init__(self, host, port, username, password):
		self.username = username
		self.password = password
		self._authenticate()

    ...

	def _authenticate(self):
		self._sendMessage_LogonRequest()
		(nonce, challengeCookie) = self._expectMessage_LogonChallenge()
		r = self._computeChallengeResponse(nonce)
		self._sendMessage_LogonResponse(r, challengeCookie)
		self.ticket = self._expectMessage_LogonSuccess()
```

### Malicious client
```python
# Abridged version of client
class Client:
    # identity =  """{"user": "admin", "groups": ["admin"]}"""
	def __init__(self, host, port, identity):
		self.username = ' '*8 + identity
		self._authenticate()

    ...

    def _authenticate(self):
    		self._sendMessage_LogonRequest()
    		(nonce, challengeCookie) = self._expectMessage_LogonChallenge()
    		ticket = b64decode(challengeCookie)[AES.block_size:]
    		self.ticket = b64encode(ticket)
```
