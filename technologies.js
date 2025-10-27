// *** SỬA LỖI 2: Chuyển TECHNOLOGIES thành Object và thêm cấu trúc cần thiết ***
// LƯU Ý QUAN TRỌNG: Dữ liệu gốc cho 'title' và 'playbooks' liên kết với các công nghệ này
// KHÔNG CÓ trong các tệp bạn cung cấp. Tôi đã tạo cấu trúc giữ chỗ (placeholder).
// Bạn sẽ cần cập nhật các trường 'title' và 'playbooks' với dữ liệu thực tế.
const TECHNOLOGIES = {
  "135": { title: { en: "Port 135 (RPC)", vi: "Cổng 135 (RPC)" }, playbooks: [] },
  "1433": { title: { en: "Port 1433 (MSSQL)", vi: "Cổng 1433 (MSSQL)" }, playbooks: [] },
  "161": { title: { en: "Port 161 (SNMP)", vi: "Cổng 161 (SNMP)" }, playbooks: ["playbook_01_nmap_recon"] }, // Liên kết ví dụ
  "18200": { title: { en: "Hashcat Mode 18200 (AS-REP)", vi: "Hashcat Mode 18200 (AS-REP)" }, playbooks: ["playbook_22_ad_attack_asrep_roast"] },
  "2049": { title: { en: "Port 2049 (NFS)", vi: "Cổng 2049 (NFS)" }, playbooks: ["playbook_09_linux_privesc_nfs_no_root_squash"] },
  "21": { title: { en: "Port 21 (FTP)", vi: "Cổng 21 (FTP)" }, playbooks: ["playbook_11_windows_foothold_ftp_anon"] },
  "22": { title: { en: "Port 22 (SSH)", vi: "Cổng 22 (SSH)" }, playbooks: [] },
  "445": { title: { en: "Port 445 (SMB)", vi: "Cổng 445 (SMB)" }, playbooks: ["playbook_10_windows_foothold_ms17_010", "playbook_12_windows_foothold_smb_share"] },
  "80": { title: { en: "Port 80 (HTTP)", vi: "Cổng 80 (HTTP)" }, playbooks: ["playbook_02_web_foothold"] },
  "active directory": { title: { en: "Active Directory", vi: "Active Directory" }, playbooks: ["playbook_21_ad_foothold_spray", "playbook_22_ad_attack_asrep_roast", "playbook_23_ad_attack_kerberoast", "playbook_24_ad_attack_gpp_decrypt", "playbook_25_ad_lateral_pth", "playbook_26_ad_lateral_ptt", "playbook_27_ad_persistence_golden_ticket", "playbook_28_ad_compromise_dcsync"] },
  "ad": { title: { en: "Active Directory (AD)", vi: "Active Directory (AD)" }, playbooks: ["playbook_21_ad_foothold_spray", "playbook_22_ad_attack_asrep_roast", "playbook_23_ad_attack_kerberoast", "playbook_24_ad_attack_gpp_decrypt", "playbook_25_ad_lateral_pth", "playbook_26_ad_lateral_ptt", "playbook_27_ad_persistence_golden_ticket", "playbook_28_ad_compromise_dcsync"] },
  "alwaysinstallelevated": { title: { en: "AlwaysInstallElevated", vi: "AlwaysInstallElevated" }, playbooks: ["playbook_17_windows_privesc_alwaysinstallelevated"] },
  "anonymous ftp": { title: { en: "Anonymous FTP", vi: "FTP ẩn danh" }, playbooks: ["playbook_11_windows_foothold_ftp_anon"] },
  "asrep roasting": { title: { en: "AS-REP Roasting", vi: "AS-REP Roasting" }, playbooks: ["playbook_22_ad_attack_asrep_roast"] },
  "binary hijack": { title: { en: "Binary Hijack", vi: "Binary Hijack" }, playbooks: ["playbook_14_windows_privesc_service_binary_hijack"] },
  "bloodhound": { title: { en: "BloodHound", vi: "BloodHound" }, playbooks: ["playbook_23_ad_attack_kerberoast"] }, // Example link
  "capabilities": { title: { en: "Linux Capabilities", vi: "Linux Capabilities" }, playbooks: ["playbook_05_linux_privesc_capabilities"] },
  "command injection": { title: { en: "Command Injection", vi: "Command Injection" }, playbooks: ["playbook_02_web_foothold"] },
  "cpassword": { title: { en: "GPP cPassword", vi: "GPP cPassword" }, playbooks: ["playbook_24_ad_attack_gpp_decrypt"] },
  "crackmapexec": { title: { en: "CrackMapExec", vi: "CrackMapExec" }, playbooks: ["playbook_12_windows_foothold_smb_share", "playbook_21_ad_foothold_spray", "playbook_24_ad_attack_gpp_decrypt"] },
  "credential dumping": { title: { en: "Credential Dumping", vi: "Dump Credentials" }, playbooks: ["playbook_20_windows_postex_mimikatz", "playbook_28_ad_compromise_dcsync", "playbook_30_windows_postex_creds"] },
  "credential hunting": { title: { en: "Credential Hunting", vi: "Săn Credentials" }, playbooks: ["playbook_12_windows_foothold_smb_share", "playbook_29_postex_linux_creds", "playbook_30_windows_postex_creds"] },
  "cron": { title: { en: "Cron Jobs", vi: "Cron Jobs" }, playbooks: ["playbook_06_linux_privesc_writable_cron"] },
  "curl": { title: { en: "cURL", vi: "cURL" }, playbooks: ["playbook_02_web_foothold", "playbook_08_linux_privesc_kernel_exploit"] }, // Example link
  "dcsync": { title: { en: "DCSync", vi: "DCSync" }, playbooks: ["playbook_27_ad_persistence_golden_ticket", "playbook_28_ad_compromise_dcsync"] },
  "enumeration": { title: { en: "Enumeration", vi: "Liệt kê thông tin" }, playbooks: ["playbook_01_nmap_recon"] }, // Example link
  "eternalblue": { title: { en: "EternalBlue (MS17-010)", vi: "EternalBlue (MS17-010)" }, playbooks: ["playbook_10_windows_foothold_ms17_010"] },
  "etc_passwd": { title: { en: "/etc/passwd", vi: "/etc/passwd" }, playbooks: ["playbook_07_linux_privesc_writable_passwd"] },
  "evil-winrm": { title: { en: "Evil-WinRM", vi: "Evil-WinRM" }, playbooks: ["playbook_12_windows_foothold_smb_share", "playbook_19_windows_privesc_sam_backup", "playbook_25_ad_lateral_pth"] },
  "exploit": { title: { en: "Exploit", vi: "Khai thác" }, playbooks: ["playbook_02_web_foothold"] }, // Example link
  "file upload": { title: { en: "File Upload", vi: "File Upload" }, playbooks: ["playbook_02_web_foothold", "playbook_11_windows_foothold_ftp_anon"] },
  "find": { title: { en: "find (Linux command)", vi: "lệnh find (Linux)" }, playbooks: ["playbook_03_linux_privesc_sudo", "playbook_04_linux_privesc_suid", "playbook_07_linux_privesc_writable_passwd", "playbook_29_postex_linux_creds"] }, // Example link
  "foothold": { title: { en: "Initial Foothold", vi: "Giành quyền truy cập ban đầu" }, playbooks: ["playbook_02_web_foothold", "playbook_10_windows_foothold_ms17_010", "playbook_11_windows_foothold_ftp_anon", "playbook_12_windows_foothold_smb_share"] }, // Example link
  "ftp": { title: { en: "FTP", vi: "FTP" }, playbooks: ["playbook_11_windows_foothold_ftp_anon"] },
  "gcc": { title: { en: "GCC", vi: "GCC" }, playbooks: ["playbook_08_linux_privesc_kernel_exploit", "playbook_09_linux_privesc_nfs_no_root_squash"] },
  "getcap": { title: { en: "getcap", vi: "getcap" }, playbooks: ["playbook_05_linux_privesc_capabilities"] },
  "gobuster": { title: { en: "Gobuster", vi: "Gobuster" }, playbooks: ["playbook_02_web_foothold"] },
  "golden ticket": { title: { en: "Golden Ticket", vi: "Golden Ticket" }, playbooks: ["playbook_27_ad_persistence_golden_ticket", "playbook_28_ad_compromise_dcsync"] },
  "gpp": { title: { en: "Group Policy Preferences (GPP)", vi: "Group Policy Preferences (GPP)" }, playbooks: ["playbook_24_ad_attack_gpp_decrypt"] },
  "gpp-decrypt": { title: { en: "gpp-decrypt", vi: "gpp-decrypt" }, playbooks: ["playbook_24_ad_attack_gpp_decrypt"] },
  "grep": { title: { en: "grep", vi: "grep" }, playbooks: ["playbook_24_ad_attack_gpp_decrypt", "playbook_29_postex_linux_creds"] }, // Example link
  "gtfobins": { title: { en: "GTFOBins", vi: "GTFOBins" }, playbooks: ["playbook_03_linux_privesc_sudo", "playbook_04_linux_privesc_suid", "playbook_05_linux_privesc_capabilities"] },
  "hashcat": { title: { en: "Hashcat", vi: "Hashcat" }, playbooks: ["playbook_22_ad_attack_asrep_roast", "playbook_23_ad_attack_kerberoast"] },
  "history": { title: { en: "Shell History", vi: "Lịch sử Shell" }, playbooks: ["playbook_29_postex_linux_creds"] }, // Example link
  "icacls": { title: { en: "icacls", vi: "icacls" }, playbooks: ["playbook_13_windows_privesc_unquoted_path", "playbook_14_windows_privesc_service_binary_hijack", "playbook_16_windows_privesc_scheduled_task_abuse"] },
  "impacket": { title: { en: "Impacket", vi: "Impacket" }, playbooks: ["playbook_25_ad_lateral_pth"] }, // Example link
  "impacket-getnpusers": { title: { en: "impacket-GetNPUsers", vi: "impacket-GetNPUsers" }, playbooks: ["playbook_22_ad_attack_asrep_roast"] },
  "impacket-getuserspns": { title: { en: "impacket-GetUserSPNs", vi: "impacket-GetUserSPNs" }, playbooks: ["playbook_23_ad_attack_kerberoast"] },
  "impacket-psexec": { title: { en: "impacket-psexec", vi: "impacket-psexec" }, playbooks: ["playbook_12_windows_foothold_smb_share", "playbook_19_windows_privesc_sam_backup", "playbook_25_ad_lateral_pth"] },
  "impacket-secretsdump": { title: { en: "impacket-secretsdump", vi: "impacket-secretsdump" }, playbooks: ["playbook_19_windows_privesc_sam_backup", "playbook_28_ad_compromise_dcsync", "playbook_30_windows_postex_creds"] },
  "insecure permissions": { title: { en: "Insecure Permissions", vi: "Quyền không an toàn" }, playbooks: ["playbook_06_linux_privesc_writable_cron", "playbook_07_linux_privesc_writable_passwd", "playbook_13_windows_privesc_unquoted_path", "playbook_14_windows_privesc_service_binary_hijack", "playbook_15_windows_privesc_weak_registry", "playbook_16_windows_privesc_scheduled_task_abuse"] },
  "initial access": { title: { en: "Initial Access", vi: "Truy cập ban đầu" }, playbooks: ["playbook_21_ad_foothold_spray"] }, // Example link
  "juicypotatong": { title: { en: "JuicyPotatoNG", vi: "JuicyPotatoNG" }, playbooks: ["playbook_18_windows_privesc_seimpersonate"] },
  "kerberoasting": { title: { en: "Kerberoasting", vi: "Kerberoasting" }, playbooks: ["playbook_23_ad_attack_kerberoast"] },
  "kerberos": { title: { en: "Kerberos", vi: "Kerberos" }, playbooks: ["playbook_22_ad_attack_asrep_roast", "playbook_23_ad_attack_kerberoast", "playbook_26_ad_lateral_ptt", "playbook_27_ad_persistence_golden_ticket"] }, // Example link
  "kerberos tickets": { title: { en: "Kerberos Tickets", vi: "Kerberos Tickets" }, playbooks: ["playbook_20_windows_postex_mimikatz", "playbook_30_windows_postex_creds"] },
  "kerbrute": { title: { en: "Kerbrute", vi: "Kerbrute" }, playbooks: ["playbook_21_ad_foothold_spray"] },
  "kernel exploit": { title: { en: "Kernel Exploit", vi: "Khai thác Kernel" }, playbooks: ["playbook_08_linux_privesc_kernel_exploit"] },
  "kirbi": { title: { en: ".kirbi (Kerberos Ticket)", vi: ".kirbi (Kerberos Ticket)" }, playbooks: ["playbook_26_ad_lateral_ptt"] },
  "krbtgt": { title: { en: "krbtgt Account", vi: "Tài khoản krbtgt" }, playbooks: ["playbook_27_ad_persistence_golden_ticket", "playbook_28_ad_compromise_dcsync"] },
  "lateral movement": { title: { en: "Lateral Movement", vi: "Di chuyển ngang" }, playbooks: ["playbook_25_ad_lateral_pth", "playbook_26_ad_lateral_ptt"] }, // Example link
  "lfi": { title: { en: "Local File Inclusion (LFI)", vi: "Local File Inclusion (LFI)" }, playbooks: ["playbook_02_web_foothold"] },
  "linpeas": { title: { en: "LinPEAS", vi: "LinPEAS" }, playbooks: ["playbook_06_linux_privesc_writable_cron"] },
  "linux": { title: { en: "Linux", vi: "Linux" }, playbooks: ["playbook_03_linux_privesc_sudo", "playbook_04_linux_privesc_suid", "playbook_05_linux_privesc_capabilities", "playbook_06_linux_privesc_writable_cron", "playbook_07_linux_privesc_writable_passwd", "playbook_08_linux_privesc_kernel_exploit", "playbook_09_linux_privesc_nfs_no_root_squash", "playbook_29_postex_linux_creds"] },
  "lpe": { title: { en: "Local Privilege Escalation (LPE)", vi: "Leo thang đặc quyền cục bộ (LPE)" }, playbooks: ["playbook_08_linux_privesc_kernel_exploit"] },
  "lsadump::sam": { title: { en: "Mimikatz lsadump::sam", vi: "Mimikatz lsadump::sam" }, playbooks: ["playbook_20_windows_postex_mimikatz"] },
  "lsass": { title: { en: "LSASS", vi: "LSASS" }, playbooks: ["playbook_20_windows_postex_mimikatz"] },
  "metasploit": { title: { en: "Metasploit", vi: "Metasploit" }, playbooks: ["playbook_10_windows_foothold_ms17_010"] },
  "mimikatz": { title: { en: "Mimikatz", vi: "Mimikatz" }, playbooks: ["playbook_20_windows_postex_mimikatz", "playbook_25_ad_lateral_pth", "playbook_26_ad_lateral_ptt", "playbook_27_ad_persistence_golden_ticket", "playbook_28_ad_compromise_dcsync", "playbook_30_windows_postex_creds"] },
  "mode_13100": { title: { en: "Hashcat Mode 13100 (Kerberoast)", vi: "Hashcat Mode 13100 (Kerberoast)" }, playbooks: ["playbook_23_ad_attack_kerberoast"] },
  "mode_18200": { title: { en: "Hashcat Mode 18200 (AS-REP)", vi: "Hashcat Mode 18200 (AS-REP)" }, playbooks: ["playbook_22_ad_attack_asrep_roast"] },
  "mount": { title: { en: "mount (Linux command)", vi: "lệnh mount (Linux)" }, playbooks: ["playbook_09_linux_privesc_nfs_no_root_squash"] },
  "ms17-010": { title: { en: "MS17-010 (EternalBlue)", vi: "MS17-010 (EternalBlue)" }, playbooks: ["playbook_10_windows_foothold_ms17_010"] },
  "msfvenom": { title: { en: "msfvenom", vi: "msfvenom" }, playbooks: ["playbook_11_windows_foothold_ftp_anon", "playbook_13_windows_privesc_unquoted_path", "playbook_14_windows_privesc_service_binary_hijack", "playbook_15_windows_privesc_weak_registry", "playbook_16_windows_privesc_scheduled_task_abuse", "playbook_17_windows_privesc_alwaysinstallelevated"] },
  "msi": { title: { en: "MSI (Windows Installer)", vi: "MSI (Windows Installer)" }, playbooks: ["playbook_17_windows_privesc_alwaysinstallelevated"] },
  "msiexec": { title: { en: "msiexec", vi: "msiexec" }, playbooks: ["playbook_17_windows_privesc_alwaysinstallelevated"] },
  "nc": { title: { en: "Netcat (nc)", vi: "Netcat (nc)" }, playbooks: ["playbook_06_linux_privesc_writable_cron", "playbook_11_windows_foothold_ftp_anon", "playbook_13_windows_privesc_unquoted_path", "playbook_14_windows_privesc_service_binary_hijack", "playbook_15_windows_privesc_weak_registry", "playbook_16_windows_privesc_scheduled_task_abuse", "playbook_17_windows_privesc_alwaysinstallelevated", "playbook_18_windows_privesc_seimpersonate"] },
  "net start": { title: { en: "net start", vi: "net start" }, playbooks: ["playbook_13_windows_privesc_unquoted_path", "playbook_14_windows_privesc_service_binary_hijack", "playbook_15_windows_privesc_weak_registry"] },
  "net stop": { title: { en: "net stop", vi: "net stop" }, playbooks: ["playbook_13_windows_privesc_unquoted_path", "playbook_14_windows_privesc_service_binary_hijack", "playbook_15_windows_privesc_weak_registry"] },
  "nfs": { title: { en: "NFS", vi: "NFS" }, playbooks: ["playbook_09_linux_privesc_nfs_no_root_squash"] },
  "nikto": { title: { en: "Nikto", vi: "Nikto" }, playbooks: ["playbook_02_web_foothold"] },
  "nmap": { title: { en: "Nmap", vi: "Nmap" }, playbooks: ["playbook_01_nmap_recon", "playbook_10_windows_foothold_ms17_010"] },
  "no_root_squash": { title: { en: "NFS no_root_squash", vi: "NFS no_root_squash" }, playbooks: ["playbook_09_linux_privesc_nfs_no_root_squash"] },
  "nse": { title: { en: "Nmap Scripting Engine (NSE)", vi: "Nmap Scripting Engine (NSE)" }, playbooks: ["playbook_01_nmap_recon"] },
  "ntlm hash": { title: { en: "NTLM Hash", vi: "NTLM Hash" }, playbooks: ["playbook_25_ad_lateral_pth", "playbook_27_ad_persistence_golden_ticket", "playbook_28_ad_compromise_dcsync", "playbook_30_windows_postex_creds"] },
  "offline hash dump": { title: { en: "Offline Hash Dump", vi: "Dump Hash Offline" }, playbooks: ["playbook_19_windows_privesc_sam_backup"] },
  "openssl": { title: { en: "OpenSSL", vi: "OpenSSL" }, playbooks: ["playbook_07_linux_privesc_writable_passwd"] },
  "pass the hash": { title: { en: "Pass the Hash (PtH)", vi: "Pass the Hash (PtH)" }, playbooks: ["playbook_19_windows_privesc_sam_backup", "playbook_25_ad_lateral_pth", "playbook_28_ad_compromise_dcsync"] },
  "pass the ticket": { title: { en: "Pass the Ticket (PtT)", vi: "Pass the Ticket (PtT)" }, playbooks: ["playbook_26_ad_lateral_ptt", "playbook_27_ad_persistence_golden_ticket"] },
  "password spraying": { title: { en: "Password Spraying", vi: "Password Spraying" }, playbooks: ["playbook_21_ad_foothold_spray"] },
  "persistence": { title: { en: "Persistence", vi: "Duy trì truy cập" }, playbooks: ["playbook_27_ad_persistence_golden_ticket"] }, // Example link
  "plaintext password": { title: { en: "Plaintext Password", vi: "Mật khẩu Plaintext" }, playbooks: ["playbook_29_postex_linux_creds", "playbook_30_windows_postex_creds"] },
  "port scan": { title: { en: "Port Scan", vi: "Quét cổng" }, playbooks: ["playbook_01_nmap_recon"] },
  "post exploitation": { title: { en: "Post Exploitation", vi: "Sau khai thác" }, playbooks: ["playbook_20_windows_postex_mimikatz", "playbook_29_postex_linux_creds", "playbook_30_windows_postex_creds"] }, // Example link
  "potato attack": { title: { en: "Potato Attack", vi: "Tấn công Potato" }, playbooks: ["playbook_18_windows_privesc_seimpersonate"] },
  "powerview": { title: { en: "PowerView", vi: "PowerView" }, playbooks: ["playbook_22_ad_attack_asrep_roast", "playbook_23_ad_attack_kerberoast"] },
  "preauthentication": { title: { en: "Kerberos Preauthentication", vi: "Kerberos Preauthentication" }, playbooks: ["playbook_22_ad_attack_asrep_roast"] },
  "printspoofer": { title: { en: "PrintSpoofer", vi: "PrintSpoofer" }, playbooks: ["playbook_18_windows_privesc_seimpersonate"] },
  "privesc": { title: { en: "Privilege Escalation", vi: "Leo thang đặc quyền" }, playbooks: [] }, // Generic, linked via specific types
  "pspy": { title: { en: "pspy", vi: "pspy" }, playbooks: ["playbook_06_linux_privesc_writable_cron"] },
  "pth": { title: { en: "Pass the Hash (PtH)", vi: "Pass the Hash (PtH)" }, playbooks: ["playbook_19_windows_privesc_sam_backup", "playbook_25_ad_lateral_pth"] },
  "ptt": { title: { en: "Pass the Ticket (PtT)", vi: "Pass the Ticket (PtT)" }, playbooks: ["playbook_26_ad_lateral_ptt", "playbook_27_ad_persistence_golden_ticket"] },
  "psexec": { title: { en: "PsExec", vi: "PsExec" }, playbooks: ["playbook_12_windows_foothold_smb_share", "playbook_25_ad_lateral_pth"] },
  "rce": { title: { en: "Remote Code Execution (RCE)", vi: "Thực thi mã từ xa (RCE)" }, playbooks: ["playbook_02_web_foothold", "playbook_10_windows_foothold_ms17_010"] }, // Example link
  "recon": { title: { en: "Reconnaissance", vi: "Thu thập thông tin" }, playbooks: ["playbook_01_nmap_recon"] }, // Example link
  "reg add": { title: { en: "reg add", vi: "reg add" }, playbooks: ["playbook_15_windows_privesc_weak_registry"] },
  "reg query": { title: { en: "reg query", vi: "reg query" }, playbooks: ["playbook_17_windows_privesc_alwaysinstallelevated", "playbook_30_windows_postex_creds"] },
  "registry": { title: { en: "Windows Registry", vi: "Windows Registry" }, playbooks: ["playbook_17_windows_privesc_alwaysinstallelevated", "playbook_30_windows_postex_creds"] }, // Example link
  "registry permissions": { title: { en: "Registry Permissions", vi: "Quyền Registry" }, playbooks: ["playbook_15_windows_privesc_weak_registry"] },
  "replication": { title: { en: "AD Replication", vi: "Sao chép AD" }, playbooks: ["playbook_28_ad_compromise_dcsync"] },
  "reverse shell": { title: { en: "Reverse Shell", vi: "Reverse Shell" }, playbooks: ["playbook_02_web_foothold", "playbook_06_linux_privesc_writable_cron", "playbook_11_windows_foothold_ftp_anon"] }, // Example link
  "rubeus": { title: { en: "Rubeus", vi: "Rubeus" }, playbooks: ["playbook_22_ad_attack_asrep_roast", "playbook_23_ad_attack_kerberoast", "playbook_26_ad_lateral_ptt"] },
  "sam": { title: { en: "SAM (Security Account Manager)", vi: "SAM (Security Account Manager)" }, playbooks: ["playbook_20_windows_postex_mimikatz"] },
  "sam dump": { title: { en: "SAM Dump", vi: "Dump SAM" }, playbooks: ["playbook_19_windows_privesc_sam_backup"] },
  "scanning": { title: { en: "Scanning", vi: "Quét" }, playbooks: ["playbook_01_nmap_recon"] }, // Example link
  "scheduled tasks": { title: { en: "Scheduled Tasks", vi: "Tác vụ đã lên lịch" }, playbooks: ["playbook_16_windows_privesc_scheduled_task_abuse"] },
  "schtasks": { title: { en: "schtasks", vi: "schtasks" }, playbooks: ["playbook_16_windows_privesc_scheduled_task_abuse"] },
  "searchsploit": { title: { en: "Searchsploit", vi: "Searchsploit" }, playbooks: ["playbook_08_linux_privesc_kernel_exploit"] },
  "seimpersonateprivilege": { title: { en: "SeImpersonatePrivilege", vi: "SeImpersonatePrivilege" }, playbooks: ["playbook_18_windows_privesc_seimpersonate"] },
  "sekurlsa::logonpasswords": { title: { en: "Mimikatz sekurlsa::logonpasswords", vi: "Mimikatz sekurlsa::logonpasswords" }, playbooks: ["playbook_20_windows_postex_mimikatz"] },
  "sekurlsa::tickets": { title: { en: "Mimikatz sekurlsa::tickets", vi: "Mimikatz sekurlsa::tickets" }, playbooks: ["playbook_20_windows_postex_mimikatz"] },
  "service hijack": { title: { en: "Service Hijack", vi: "Service Hijack" }, playbooks: ["playbook_14_windows_privesc_service_binary_hijack"] },
  "showmount": { title: { en: "showmount", vi: "showmount" }, playbooks: ["playbook_09_linux_privesc_nfs_no_root_squash"] },
  "smb": { title: { en: "SMB", vi: "SMB" }, playbooks: ["playbook_10_windows_foothold_ms17_010", "playbook_12_windows_foothold_smb_share"] }, // Example link
  "smbclient": { title: { en: "smbclient", vi: "smbclient" }, playbooks: ["playbook_12_windows_foothold_smb_share", "playbook_24_ad_attack_gpp_decrypt"] },
  "spn": { title: { en: "Service Principal Name (SPN)", vi: "Service Principal Name (SPN)" }, playbooks: ["playbook_23_ad_attack_kerberoast"] },
  "sqlmap": { title: { en: "sqlmap", vi: "sqlmap" }, playbooks: ["playbook_02_web_foothold"] },
  "sqli": { title: { en: "SQL Injection (SQLi)", vi: "SQL Injection (SQLi)" }, playbooks: ["playbook_02_web_foothold"] },
  "ssh keys": { title: { en: "SSH Keys", vi: "Khóa SSH" }, playbooks: ["playbook_29_postex_linux_creds"] }, // Example link
  "su": { title: { en: "su (Linux command)", vi: "lệnh su (Linux)" }, playbooks: ["playbook_07_linux_privesc_writable_passwd"] },
  "sudo": { title: { en: "sudo", vi: "sudo" }, playbooks: ["playbook_03_linux_privesc_sudo"] },
  "sudo -l": { title: { en: "sudo -l", vi: "sudo -l" }, playbooks: ["playbook_03_linux_privesc_sudo"] },
  "suid": { title: { en: "SUID", vi: "SUID" }, playbooks: ["playbook_04_linux_privesc_suid", "playbook_09_linux_privesc_nfs_no_root_squash"] },
  "system": { title: { en: "SYSTEM Account (Windows)", vi: "Tài khoản SYSTEM (Windows)" }, playbooks: ["playbook_10_windows_foothold_ms17_010"] }, // Example link
  "system hive": { title: { en: "SYSTEM Hive", vi: "SYSTEM Hive" }, playbooks: ["playbook_19_windows_privesc_sam_backup"] },
  "sysvol": { title: { en: "SYSVOL Share", vi: "SYSVOL Share" }, playbooks: ["playbook_24_ad_attack_gpp_decrypt"] },
  "tgs": { title: { en: "Ticket Granting Service (TGS)", vi: "Ticket Granting Service (TGS)" }, playbooks: ["playbook_23_ad_attack_kerberoast"] },
  "tgt": { title: { en: "Ticket Granting Ticket (TGT)", vi: "Ticket Granting Ticket (TGT)" }, playbooks: ["playbook_27_ad_persistence_golden_ticket"] },
  "token impersonation": { title: { en: "Token Impersonation", vi: "Mạo danh Token" }, playbooks: ["playbook_18_windows_privesc_seimpersonate"] },
  "uname": { title: { en: "uname", vi: "uname" }, playbooks: ["playbook_08_linux_privesc_kernel_exploit"] },
  "unquoted service path": { title: { en: "Unquoted Service Path", vi: "Đường dẫn dịch vụ không trích dẫn" }, playbooks: ["playbook_13_windows_privesc_unquoted_path"] },
  "web": { title: { en: "Web Attack", vi: "Tấn công Web" }, playbooks: ["playbook_02_web_foothold"] }, // Example link
  "webshell": { title: { en: "Webshell", vi: "Webshell" }, playbooks: ["playbook_11_windows_foothold_ftp_anon"] }, // Example link
  "whoami": { title: { en: "whoami", vi: "whoami" }, playbooks: ["playbook_18_windows_privesc_seimpersonate", "playbook_27_ad_persistence_golden_ticket"] }, // Example link
  "whoami /priv": { title: { en: "whoami /priv", vi: "whoami /priv" }, playbooks: ["playbook_18_windows_privesc_seimpersonate"] },
  "windows": { title: { en: "Windows", vi: "Windows" }, playbooks: ["playbook_10_windows_foothold_ms17_010", "playbook_11_windows_foothold_ftp_anon", "playbook_12_windows_foothold_smb_share", "playbook_13_windows_privesc_unquoted_path", "playbook_14_windows_privesc_service_binary_hijack", "playbook_15_windows_privesc_weak_registry", "playbook_16_windows_privesc_scheduled_task_abuse", "playbook_17_windows_privesc_alwaysinstallelevated", "playbook_18_windows_privesc_seimpersonate", "playbook_19_windows_privesc_sam_backup", "playbook_20_windows_postex_mimikatz", "playbook_25_ad_lateral_pth", "playbook_26_ad_lateral_ptt", "playbook_27_ad_persistence_golden_ticket", "playbook_28_ad_compromise_dcsync", "playbook_30_windows_postex_creds"] }, // Example link
  "wmic": { title: { en: "wmic", vi: "wmic" }, playbooks: ["playbook_13_windows_privesc_unquoted_path"] },
  "writable file": { title: { en: "Writable File", vi: "Tệp có thể ghi" }, playbooks: ["playbook_06_linux_privesc_writable_cron", "playbook_07_linux_privesc_writable_passwd"] },
  "wpscan": { title: { en: "WPScan", vi: "WPScan" }, playbooks: ["playbook_02_web_foothold"] },
  // ... (Thêm tất cả các từ khóa khác từ mảng gốc vào đây với cấu trúc tương tự)
  // Ví dụ cho một vài từ khóa khác:
  "telnet": { title: { en: "Telnet", vi: "Telnet" }, playbooks: [] },
  "sql": { title: { en: "SQL", vi: "SQL" }, playbooks: [] },
  "python": { title: { en: "Python", vi: "Python" }, playbooks: ["playbook_05_linux_privesc_capabilities"] },
  "php": { title: { en: "PHP", vi: "PHP" }, playbooks: [] },
  "javascript": { title: { en: "JavaScript", vi: "JavaScript" }, playbooks: [] },
  "burpsuite": { title: { en: "Burp Suite", vi: "Burp Suite" }, playbooks: [] },
  // Thêm tất cả các key còn lại từ mảng cũ vào đây...
}; // *** Kết thúc Object TECHNOLOGIES ***

