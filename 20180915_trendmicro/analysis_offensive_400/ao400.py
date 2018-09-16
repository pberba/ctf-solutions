# REQUIRED: PyCrypto 2.6.1
#     To install: pip install pycrypto
#     Homepage: https://www.dlitz.net/software/pycrypto/

import argparse
import sys
import socket
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from base64 import b64encode, b64decode


def readNullTerminatedString(f):
	buf = b''
	while True:
		if len(buf) > 1 << 20:
			raise Exception("Overly long input")
		c = f.read(1)
		if len(c) == 0:
			raise Exception("End of stream reached")
		if ord(c) == 0:		# Indicates NULL termination of a UTF-8 string.
			break
		buf += c
	return unicode(buf, encoding="utf-8", errors="strict")

def toNullTerminatedUtf8(s):
	return unicode(s).encode("utf-8") + "\x00"
	

class Client:

	nonceLengthInBytes = 8

	def __init__(self, host, port):
		self.username = "_"*8 + """{"user": "admin", "groups": ["admin"]}"""
		self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._socket.setblocking(1)
		self._socket.connect((host, port))
		self._f = self._socket.makefile("rw")
		self._authenticate()
		
	def close():
		self._f.close()
		self._socket.close()
		
	def execute(self, command):
		self._sendMessage_Command(command)
		return self._expectMessage_CommandResult()
		
	def _authenticate(self):
		self._sendMessage_LogonRequest()
		(nonce, challengeCookie) = self._expectMessage_LogonChallenge()
		ticket = b64decode(challengeCookie)[AES.block_size:]
		self.ticket = b64encode(ticket)
		
	def _sendMessage_LogonRequest(self):
		self._f.write("\x01")
		self._f.write(toNullTerminatedUtf8(self.username))
		self._f.flush()
		
	def _expectMessage_LogonChallenge(self):
		self._expectMessageType(0x02)
		nonce = self._readBytes(self.nonceLengthInBytes)
		challengeCookie = self._expectString()
		return (nonce, challengeCookie)
			
	def _sendMessage_Command(self, command):
		self._f.write("\x06")
		self._f.write(toNullTerminatedUtf8(self.ticket))
		self._f.write(toNullTerminatedUtf8(command))
		self._f.flush()

	def _expectMessage_CommandResult(self):
		messageType = self._readMessageType()
		if messageType == 0x07:
			result = self._expectString()
			return result
		elif messageType == 0x05:
			sys.stderr.write("Unauthorized\n")
			exit(1)
		else:
			raise Exception("Unexpected message type: 0x%02x" % messageType)

	def _readMessageType(self):
		messageTypeByte = self._readBytes(1)
		if (len(messageTypeByte) == 0):
			raise Exception("Server has disconnected")
		return ord(messageTypeByte)
		
	def _expectMessageType(self, expectedMessageType):
		messageType = self._readMessageType()
		if messageType != expectedMessageType:
			raise Exception("Unexpected message type: 0x%02x" % messageType)
	
	def _readBytes(self, nBytes):
		result = self._f.read(nBytes)
		print(result)
		if len(result) != nBytes:
			raise Exception("Connection was closed")
		return result
		
	def _expectString(self):
		buf = b''
		while True:
			if len(buf) > 1 << 20:
				raise Exception("Overly long input")
			c = self._f.read(1)
			if len(c) == 0:
				raise Exception("End of stream reached")
			if ord(c[0]) == 0:		# Indicates NULL termination of a UTF-8 string.
				break
			buf += c
		return unicode(buf, encoding="utf-8", errors="strict")

	
			
		
if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("host")
	parser.add_argument("port", type=int)
	parser.add_argument("command")
	args = parser.parse_args()
	client = Client(args.host, args.port)
	if not client.ticket:
		sys.stderr.write("Failed to authenticate\n")
		exit(1)
	print client.execute(args.command)
# TMCTF{90F41EF71ED5}