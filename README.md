# sockdump

Dump unix domain socket traffic.

## Requirement

- bcc

## Example

### string output

```
$ sudo ./sockdump.py --format string /var/run/docker.sock
waiting for data
19:23:06.633 >>> process docker [31042 -> 13710] len 81(81)
HEAD /_ping HTTP/1.1
Host: docker
User-Agent: Docker-Client/19.03.5 (linux)

19:23:06.633 >>> process dockerd [13710 -> 31042] len 280(280)
HTTP/1.1 200 OK
Api-Version: 1.40
Cache-Control: no-cache, no-store, must-revalidate
Content-Length: 0
Content-Type: text/plain; charset=utf-8
Docker-Experimental: false
Ostype: linux
Pragma: no-cache
Server: Docker/19.03.5 (linux)
Date: Fri, 20 Dec 2019 03:23:06 GMT

19:23:06.633 >>> process docker [31042 -> 13710] len 96(96)
GET /v1.40/containers/json HTTP/1.1
Host: docker
User-Agent: Docker-Client/19.03.5 (linux)

19:23:06.633 >>> process dockerd [13710 -> 31042] len 204(204)
HTTP/1.1 200 OK
Api-Version: 1.40
Content-Type: application/json
Docker-Experimental: false
Ostype: linux
Server: Docker/19.03.5 (linux)
Date: Fri, 20 Dec 2019 03:23:06 GMT
Content-Length: 3

[]
^C
4 packets captured
```

### pcap output

```
$ sudo ./sockdump.py /var/run/docker.sock --format pcap --output dump
waiting for data
^C
8 packets captured
$ wireshark -X lua_script:wireshark/dummy.lua dump
```
![wireshark](wireshark/wireshark.jpg)
