Below is a full, “GitHub-ready” package that includes all the scripts—with comments and usage instructions—and a complete plan that integrates our BusyBox emergency toolkit and even leverages **chattr** to help protect key files. This package is designed for rapid deployment during the competition, letting you harden your systems, detect and misdirect the Red Team, and preserve evidence.

You can copy/paste all of this into a GitHub repository (for example, “_BlueTeam_Deception”) and then print the scripts (if printed copies are required) or load them from a USB drive.

---

#  Blue Team Deception & Hardening Toolkit

This repository contains a set of scripts and instructions to be deployed in a rapid 30-minute window to fortify your RHEL systems against a persistent Red Team. The toolkit includes:

- **redkiller.sh** – Rapid scanning for Red Team persistence and rogue elements  
- **harden.sh** – System hardening (disabling unneeded services, tightening SSH, etc.)  
- **monitor.sh** – Deploy auditd and inotify monitoring to log changes in critical files  
- **honey.sh** – Set up decoy/honeypot services and bait accounts  
- **recoveryprep.sh** – Baseline snapshots for incident reporting and recovery  
- **busybox_setup.sh** – Installs a static BusyBox toolkit to override compromised binaries  
- **chattr_protect.sh** – Uses `chattr +i` to lock down critical files, preventing unauthorized changes  
- **sneaky_deploy.sh** – A master deployment script that (optionally) deploys additional deceptive artifacts, such as fake backdoors, decoy web shells, and more

The package is built around the idea of “weaponized deception”—showing the Red Team that your box is already so “ruined” (or overly monitored) that they will waste time chasing ghosts while your critical services remain available.

---

## Usage Plan

1. **Initial Deployment (0 – 5 Minutes):**  
   - Boot the system (or log in as root) and deploy critical changes.
   - Run `redkiller.sh` to scan for rogue users, SUID binaries, unauthorized cronjobs, and suspicious artifacts.
   - Immediately run `harden.sh` to disable unnecessary services, enforce SSH hardening, and lock out non-essential users.

2. **Monitoring & Logging (5 – 10 Minutes):**  
   - Start `monitor.sh` to set up auditd and inotify-based real-time monitoring.
   - Use `chattr_protect.sh` to mark important system files (and your deployed scripts) as immutable—making it harder for Red Team to tamper with your defense.

3. **Deception Deployment (10 – 15 Minutes):**  
   - Execute `honey.sh` to create bait users (e.g., “honeybadger”) and deploy decoy services (e.g., a fake open port that echoes /etc/passwd).
   - Run the BusyBox toolkit deployment (`busybox_setup.sh`) to ensure you have a fallback shell and basic utilities if your native binaries are compromised.

4. **Baseline Recovery & Additional Deception (15 – 20 Minutes):**  
   - Run `recoveryprep.sh` to capture the system’s baseline state (hashes, open ports, process list, etc.) so that any deviations are logged.
   - Use `sneaky_deploy.sh` (optional module) to deploy extra decoy artifacts like a fake backdoor, decoy web shells, or “Zombie” processes that force the Red Team to chase phantom processes.

5. **Continuous Operations (20 – 30 Minutes and Beyond):**  
   - Check your log files in `/var/log/.alerts.log` and monitor audit log events.
   - Use the immutable logs protected by `chattr` so they cannot be wiped.
   - Report suspicious activity and use captured evidence in injects or incident reports.

---

## File List and Code

Below are all the scripts with comprehensive comments and code.

### File: **redkiller.sh**
```bash
#!/bin/bash
# redkiller.sh — Rapid Forensics + Kill-Switch for RHEL Blue Team
# Must be run as root.
# Scans for rogue users, SUID binaries, suspicious cronjobs, and backdoor signs.
# Logs all output to /root/red_purge.log

LOG="/root/red_purge.log"
touch "$LOG" && chmod 600 "$LOG"

echo "[*] STARTING RED TEAM PURGE" | tee -a "$LOG"

# 1. Lock rogue users (UID ≥ 1000, excluding blueadmin)
echo "[*] Checking for unauthorized users..." | tee -a "$LOG"
awk -F: '$3 >= 1000 && $1 != "blueadmin"' /etc/passwd | tee -a "$LOG"
for user in $(awk -F: '$3 >= 1000 && $1 != "blueadmin"' /etc/passwd); do
    usermod -L "$user" && echo "Locked user: $user" | tee -a "$LOG"
done

# 2. Locate rogue SUID binaries outside standard directories
echo "[*] Checking for rogue SUID binaries..." | tee -a "$LOG"
find / -perm -4000 -type f 2>/dev/null | grep -vE '^/(bin|sbin|usr/bin|usr/sbin)/' | tee -a "$LOG"

# 3. Check root cron jobs
echo "[*] Checking for root cron jobs..." | tee -a "$LOG"
[ -f /var/spool/cron/root ] && cat /var/spool/cron/root | tee -a "$LOG"
ls -l /etc/cron* /var/spool/cron/crontabs /etc/anacrontab /etc/at.* 2>/dev/null | tee -a "$LOG"

# 4. Scan for unusual open ports (exclude common allowed ports)
echo "[*] Scanning for unknown open ports..." | tee -a "$LOG"
ss -tulnp | grep -vE ':(22|80|443|53|389|5432|445|25|587)\b' | tee -a "$LOG"

# 5. Check for suspicious preload hooks in /etc/ld.so.* and odd bashrc entries
echo "[*] Checking for preload/bashrc backdoors..." | tee -a "$LOG"
grep -i preload /etc/ld.so.* 2>/dev/null | tee -a "$LOG"
grep -i bash /root/.bashrc /home/*/.bashrc 2>/dev/null | tee -a "$LOG"

# 6. Review sudoers for unauthorized modifications
echo "[*] Verifying sudo access..." | tee -a "$LOG"
grep -vE '^#|^$' /etc/sudoers | tee -a "$LOG"
for f in /etc/sudoers.d/*; do 
    echo "==== $f ===="; 
    cat "$f"; 
done 2>/dev/null | tee -a "$LOG"

# 7. Search for reverse shell patterns in common directories
echo "[*] Searching for reverse shell code..." | tee -a "$LOG"
grep -RiE 'curl|wget|nc|bash -i|telnet' /etc /var /home /tmp /root 2>/dev/null | tee -a "$LOG"

echo "[+] Red killer scan complete. Check $LOG for results."
```

---

### File: **harden.sh**
```bash
#!/bin/bash
# harden.sh — Harden RHEL for  Blue Team
# Must be run as root.
# Disables unneeded services, tightens SSH configuration, and locks out non-blueadmin users.

# Disable unnecessary services
for svc in bluetooth avahi-daemon cups rpcbind nfs-server; do
    systemctl disable --now "$svc" 2>/dev/null
done

# SSH Hardening: update configuration and restart sshd
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i 's/^#*Port .*/Port 2222/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
grep -q '^AllowUsers blueadmin' /etc/ssh/sshd_config || echo 'AllowUsers blueadmin' >> /etc/ssh/sshd_config
systemctl restart sshd

# Kernel parameters hardening via sysctl
cat <<EOF >> /etc/sysctl.conf
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.rp_filter=1
EOF
sysctl -p

# Disable cron for non-root by denying all other users
echo "ALL" > /etc/cron.deny

# Lock all non-blueadmin users (UID >= 1000)
for user in $(awk -F: '$3 >= 1000 && $1 != "blueadmin"' /etc/passwd); do
    usermod -L "$user"
done

echo "[+] System hardened successfully."
```

---

### File: **monitor.sh**
```bash
#!/bin/bash
# monitor.sh — Deploys file and configuration monitoring.
# Must be run as root.
# Uses auditd and inotifywait to log changes to critical files.

ALERT_LOG="/var/log/.alerts.log"
touch "$ALERT_LOG"
chmod 600 "$ALERT_LOG"

# Set up audit rules for critical files
cat <<EOF > /etc/audit/rules.d/monitor.rules
-w /etc/passwd -p wa -k passwd_mod
-w /etc/shadow -p wa -k shadow_mod
-w /etc/ssh/sshd_config -p wa -k ssh_conf_mod
EOF
augenrules --load

# Deploy an inotify watcher to catch real-time changes
cat << 'EOF' > /usr/local/bin/watch_critical.sh
#!/bin/bash
inotifywait -m -e modify,delete /etc/passwd /etc/shadow /root/.bash_history /home/*/.bash_history /bin /usr/bin |
while read path action file; do
  echo "$(date): ALERT: $file was $action in $path" >> /var/log/.alerts.log
done
EOF

chmod +x /usr/local/bin/watch_critical.sh
nohup /usr/local/bin/watch_critical.sh & disown

echo "[+] Monitoring deployed."
```

---

### File: **honey.sh**
```bash
#!/bin/bash
# honey.sh — Deploy decoy elements to misdirect the Red Team.
# Must be run as root.
# Creates a fake user and deploys bait on a non-standard port.

# Create decoy user "honeybadger" and set a default password
useradd -m honeybadger -s /bin/bash
echo 'honeybadger:P@ssw0rd123' | chpasswd

# Configure PAM to call a logging script upon login by the decoy user
echo "session optional pam_exec.so /usr/local/bin/honey_alert.sh" >> /etc/pam.d/sshd
cat << 'EOF' > /usr/local/bin/honey_alert.sh
#!/bin/bash
echo "$(date): Honeybadger login detected from $PAM_RHOST" >> /var/log/.alerts.log
EOF
chmod +x /usr/local/bin/honey_alert.sh

# Deploy a decoy open port (31337) that echoes a sensitive file to misdirect attackers
yum install -y socat
nohup socat TCP-LISTEN:31337,fork EXEC:'/bin/cat /etc/passwd' & disown

echo "[+] Honeypot deployed."
```

---

### File: **recoveryprep.sh**
```bash
#!/bin/bash
# recoveryprep.sh — Capture a baseline snapshot of system state.
# Must be run as root.
# Records hashes, open ports, running processes, and user data for incident reporting.

mkdir -p /root/baseline

find /bin /sbin /usr/bin /usr/sbin -type f -exec sha256sum {} + > /root/baseline/hashes.txt
ss -tuln > /root/baseline/ports.txt
ps aux > /root/baseline/processes.txt
getent passwd > /root/baseline/users.txt

tar czf /root/baseline_$(date +%F).tar.gz -C /root baseline

echo "[+] Baseline archived at /root/baseline_$(date +%F).tar.gz"
```

---

### File: **busybox_setup.sh**
```bash
#!/bin/bash
# busybox_setup.sh — Deploy a static BusyBox toolkit as an emergency fallback.
# Must be run as root.
# In case key utilities become compromised, BusyBox provides a minimal, trusted set.

# Assumes a statically compiled busybox binary (named busybox-x86_64) is present.
mkdir -p /opt/busybox
cp busybox-x86_64 /opt/busybox/busybox
chmod +x /opt/busybox/busybox

# Create symlinks for common commands
for cmd in ls ps top grep netstat ip rm mv cp bash sh mkdir touch chmod chown ping nc wget curl kill killall; do
    ln -sf /opt/busybox/busybox /opt/busybox/"$cmd"
done

# Prepend the BusyBox directory to the blueadmin user's PATH to ensure fallback usage
echo 'export PATH=/opt/busybox:$PATH' >> /home/blueadmin/.bashrc

echo "[+] BusyBox toolkit deployed to /opt/busybox."
```

---

### File: **chattr_protect.sh**
```bash
#!/bin/bash
# chattr_protect.sh — Use chattr to lock down critical files from modification.
# Must be run as root.
# Protects key configuration files and deployed scripts from unauthorized changes.

# Protect SSH configuration, audit logs, and the deployed toolkit scripts
chattr +i /etc/ssh/sshd_config
chattr +i /var/log/.alerts.log
chattr +i /mnt/data/PCDC_Script_Kit/redkiller.sh
chattr +i /mnt/data/PCDC_Script_Kit/harden.sh
chattr +i /mnt/data/PCDC_Script_Kit/monitor.sh
chattr +i /mnt/data/PCDC_Script_Kit/honey.sh
chattr +i /mnt/data/PCDC_Script_Kit/recoveryprep.sh

echo "[+] Critical files marked immutable using chattr."
```

> **Note:** Use `chattr -i <file>` to remove protection before applying updates.

---

### File: **sneaky_deploy.sh**
```bash
#!/bin/bash
# sneaky_deploy.sh — Optional extra layer of deception and misdirection.
# Must be run as root.
# Deploy additional decoy artifacts to further waste Red Team time.
# Toggle each section as needed.

# --- 1. Fake Red Team Backdoor (Creates fake files and logs)
mkdir -p /opt/.reptile /opt/.loki
touch /opt/.reptile/.keylogger /opt/.loki/.reverse_shell
echo -e '#!/bin/bash\necho "Contacting C2..."' > /usr/local/bin/.start_payload
chmod +x /usr/local/bin/.start_payload
echo "cron job installed by redteam" >> /var/log/secure
logger -p authpriv.notice "RedTeam tool loaded at PID $$"

# --- 2. Decoy "Scoring Service" on port 8888
yum install -y socat httpd-tools
nohup socat TCP4-LISTEN:8888,fork SYSTEM:'echo -e "HTTP/1.1 200 OK\\n\\nScoringService Alive: $(date)"' & disown

# --- 3. Fake Config Backup with Juicy Fake Creds
mkdir -p /opt/backups
cat <<EOF > /opt/backups/nginx.conf.bak
server {
  listen 80;
  root /var/www/html;
  # admin panel
  location /admin {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
  }
}

# credentials for internal tools
# DO NOT SHARE!
# admin:ThisIsNotThePassword123
# root:abc123!
EOF
auditctl -w /opt/backups/nginx.conf.bak -p r -k baitread

# --- 4. Idle Port Trap (Fake shell on port 5555)
nohup socat TCP4-LISTEN:5555,fork EXEC:'/bin/echo "AdminShell v1.1; $(id); $(whoami)"' & disown

echo "[+] Sneaky deploy complete."
```

---

## Final Notes & Reminders

- **Deploy order:**  
  1. Run `redkiller.sh`  
  2. Run `harden.sh`  
  3. Run `monitor.sh`  
  4. Run `chattr_protect.sh` to lock down key files  
  5. Run `honey.sh`  
  6. Run `busybox_setup.sh`  
  7. Run `recoveryprep.sh`  
  8. Optionally, run `sneaky_deploy.sh` for added deception

- **Log files:** All logs are stored (e.g., `/var/log/.alerts.log`, `/root/red_purge.log`), so you can back them up and use them for incident reports and inject submissions.

- **Immutable files:** Remember to remove the immutable flag (`chattr -i <file>`) if you need to update any protected file later during the contest.

---

This entire repository, when deployed, should provide you with robust, layered defenses, plenty of red herrings to distract the Red Team, and comprehensive logs for reporting and scoring injects—all while ensuring your critical services remain unaffected and online.

Let me know if you need any further modifications or additional deployable modules. Happy defending!
