# noxCTF 2018: Slippery Situtation

__Tags:__ `misc`, `stego`  
__Total Solvers:__ 27  
__Total Points:__ 750

## Problem Statement

Something slippery is happening here, this virus scan website smells fishy, thats why its slippy, I need to get to the control panel and see whats going on.

`http://chal.noxale.com:1336`

```html
<!DOCTYPE html>
<html lang="en"><head>
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
  <title>ZIP ANALYZER</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="ZIP%20ANALYZER_files/bootstrap.css">
  <script src="ZIP%20ANALYZER_files/jquery.js"></script>
  <script src="ZIP%20ANALYZER_files/bootstrap.js"></script>
</head>
<body>
    <br><br><br><br><br>
    <center>
        <h1>Welcome to the zip analysis demo!</h1>
        <h4>our amazing software will take your zip, unpack it and scan it for viruses</h4>
        <h4>we also track everything you do on this website in our admin control panel that is unbreachable, unhackable</h4>
        <h4>thanks to our amazing cyber-security team</h4>
        <h4>How does it work?</h4>
        <h5>You upload a zip file, our servers extract the file using bash command "unzip -: file.zip"</h5>
        <h5>the server scans the files inside and returns results!</h5>
        <h6>We dont believe in containers, all zip files are uploaded to /files/ directory and get extracted there for maximum security!</h6>
        <br><br><br>
            <form method="post" enctype="multipart/form-data" action="/upload">
                <input class="form-control" name="file" accept="application/zip,application/x-zip,application/x-zip-compressed" type="file">
                <br>
                <input class="btn btn-primary" value="Upload .zip file" type="submit">
            </form>
    </center>
<!-- Note to self : admin page link : /admin-->

</body></html>
```


## Solution

Based on the prompt in the _ZIP ANALYZER_ page and the name __slippery situation__, it is obviously a reference to the recent [Zip Slip Vulnerability](https://snyk.io/research/zip-slip-vulnerability).

We go to the comment `<!-- Note to self : admin page link : /admin-->`

We get the admin panel where we see another comment in the HTML.

```
    <!-- Note to self so i wont forget : if a file named key.txt containing the short ssid is found in the ./admin directory then you dont need to login with user and pass to save time -->
```

Since the zip in decompressed in the `/files/` directory, we create a zip adds a file `../admin/key.text`. This text file does not have to contain anything to work. It's probably a bug.


```bash
$ zip ../admin/key.txt
```

Uploading this zip, and revisiting the admin web panel, we greeted by an encoded message.
```
VGhpcyBwYWdlIGlzIG9ubHkgYXZhaWxhYmxlIGZvciBBZG1pblBhbmVsIGJyb3dzZXIgdXNlcnMuDQoNCkFkbWluUGFuZWwvMC4xIGFnZW50
IHVzZXJzIG9ubHkh
```

Which when decoded gives us,
```bash
$ echo VGhpcyBwYWdlIGlzIG9ubHkgYXZhaWxhYmxlIGZvciBBZG1pblBhbmVsIGJyb3dzZXIgdXNlcnMuDQoNCkFkbWluUGFuZWwvMC4xIGFnZW50
IHVzZXJzIG9ubHkh | base64 -d
This page is only available for AdminPanel browser users.

AdminPanel/0.1 agent users only!%    
```

We redo our request with that user agent and we get the flag.

`noxCTF{Z1p_Fil3s_Ar3_Fun_H4ha}``
