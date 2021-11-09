#### Weak RSA (225 points, 157 solves)

##### Problem

In this you are just given:
- `pubkey.pem`: RSA public key file
- `flag.enc`: an encrypted flag.

##### Solution

When these are all that is given in CTF competitions, it should be clear that it is really trying to "crack" the RSA public key to recover the private key. 

For these types of questions, always to use [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) which has a suite of well known attacks on weak RSA keys. If it fails, then we can start analyzing the problem deeper.

```
/opt/RsaCtfTool/RsaCtfTool.py --publickey "pubkey.pem" --uncipherfile flag.enc
```

See `solution_output.txt` to see the output of the command above.