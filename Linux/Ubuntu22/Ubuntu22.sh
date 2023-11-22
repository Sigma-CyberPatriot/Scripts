#!/bin/bash

# To get this script to work, run "chmod +x ./main.sh"
# To find all apt apps installed, run "apt list --installed"
# Please run this script as root.

# Variables
pass="SigmaCyberPatriot23!"

# This is the main function.  It acts as a menu.
function main {
    printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
    printf "   ______    ______    ______    __       __    ______               __      __    ________    __            ________   \n"
    printf "  /      \  /      |  /      \  /  \     /  |  /      \             /  |    /  |  /        \  /  |          /        \  \n"
    printf " /&&&&&&  | &&&&&&/  /&&&&&&  | &&  \   /&& | /&&&&&&  |            && |    && | /&&&&&&&&  | && |         /&&&&&&&&  | \n"
    printf " && \__&&/    && |   && | _&&/  &&$  \ /&&$ | && |__&& |   ______   && |    && | && |    && | && |         && |    && | \n"
    printf " &&      \    && |   && |/    | &&&&  /&&&& | &&    && |  |______|  && |    && | && |    && | && |         && |    && | \n"
    printf "  &&&&&&  |   && |   && |&&&& | && && &&/&& | &&&&&&&& |            &&&&&&&&&& | && |    && | && |         && |    && | \n"
    printf " /  \__&& |  _&& |_  && \__&& | && |&&$/ && | && |  && |            && |    && | && |    && | && |_______  && |    && | \n"
    printf " &&    && / / &&   | &&    && / && | $/  && | && |  && |            && |    && | && \    && | &&         | && \    && | \n"
    printf "  &&&&&&_/  &&&&&&_/  &&&&&&_/  &&_/     &&_/ &&_/  &&_/            &&_/    &&_/  &&&&&&&&_/  &&&&&&&&&&_/  &&&&&&&&_/  \n"
    printf "             __     __   _______    __     __   ___      __   ________   __     __        ______     ______             \n"
    printf "            /  |   /  | /       \  /  |   /  | /   \    /  | /        | /  |   /  |      /      \   /      \            \n"
    printf "            && |   && | &&&&&&&  \ && |   && | &&&& \   && | &&&&&&&&_/ && |   && |     /&&&&&&  | /&&&&&&  |           \n"
    printf "            && |   && | && |  && | && |   && | && && \  && |    && |    && |   && |     &&_/  && | &&_/  && |           \n"
    printf "            && |   && | && |  && / && |   && | && &&  \ && |    && |    && |   && |           && |       && |           \n"
    printf "            && |   && | &&&&&&& <  && |   && | && | && \&& |    && |    && |   && |          && /       && /            \n"
    printf "            && |   && | && |  && \ && |   && | && | &&  && |    && |    && |   && |        &&& /      &&& /             \n"
    printf "            && |   && | && |  && | && |   && | && |  && && |    && |    && |   && |      &&&  /___  &&&  /___           \n"
    printf "             &&&&&&&_/  &&&&&&&__/  &&&&&&&_/  &&_/   &&&&_/    &&_/     &&&&&&&_/      &&&&&&&&_/ &&&&&&&&_/           \n"
    printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Written by: Jackson Campbell ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
    printf "    1) Start                                                                                                            \n"
    printf "    2) Edit ports                                                                                                       \n"
    printf "    3) Update Firefox Policies (Deprecated)                                                                             \n"
    printf "    4) View checklist                                                                                                   \n"
    printf "    5) Exit Program                                                                                                     \n"
    printf "                                                                                                                        \n"
    printf "    Disclaimers:                                                                                                        \n"
    printf "        This program does not any passwords.  This needs to be done manually.                                           \n"
    printf "        Note that any new groups will be empty, as you cannot make lists of lists.                                      \n"
    printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
 
    read -r answer
    if [ "$answer" -eq 1 ]
        then auto;
    elif [ "$answer" -eq 2 ]
        then managePorts;
    elif [ "$answer" -eq 3 ]
        then firefoxPolicies;
    elif [ "$answer" -eq 4 ]
        then checklist;
    elif [ "$answer" -eq 5 ]
        then exit;
    else
        main;
    fi
}

# This function contains most of the things that an ubuntu image will need done.
function auto {
    # Differences  -- Implement later
    # Editing host.conf
    #cp /etc/host.conf /etc/host.conf.bak
    #echo "nospoof on" | tee -a /etc/host.conf
    #echo "order bind,hosts" | tee -a /etc/host.conf
    #ip link set dev promisc off
 
    # Installing apt-get
    wget http://us.archive.ubuntu.com/ubuntu/pool/main/a/apt/libapt-pkg6.0_2.4.11_amd64.deb -O libapt.deb
    wget http://us.archive.ubuntu.com/ubuntu/pool/main/a/apt/apt_2.4.11_amd64.deb -O apt.deb
    wget http://us.archive.ubuntu.com/ubuntu/pool/main/a/apt/apt-utils_2.4.11_amd64.deb -O apt-utils.deb
    dpkg -i libapt.deb 
    dpkg -i apt.deb
    dpkg -i apt-utils.deb

    CODENAME=$(lsb_release -cs)
    # Editing sources.list
    echo "deb http://us.archive.ubuntu.com/ubuntu $CODENAME main multiverse restricted universe" | tee /etc/apt/sources.list
    echo "deb http://us.archive.ubuntu.com/ubuntu $CODENAME-security main multiverse restricted universe" | tee -a /etc/apt/sources.list
    echo "deb http://us.archive.ubuntu.com/ubuntu $CODENAME-updates main multiverse restricted universe" | tee -a /etc/apt/sources.list
    echo "deb http://archive.canonical.com/ubuntu $CODENAME partner" | tee -a /etc/apt/sources.list
 
    # Making installs require secure ssl connection
    apt-get install -y wget ca-certificates
    wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -
    echo "deb http://apt.postgresql.org/pub/repos/apt/ $CODENAME-pgdg main" | tee -a /etc/apt/sources.list.d/pgdg.list
 
    # Updating all apps (snaps included)
    apt-get update
    apt-get upgrade -y
    snap refresh
 
    # Installing apps
    apt-get install -y auditd
    apt-get install -y chkrootkit
    apt-get install -y clamav
    apt-get install -y cron
    apt-get install -y firewalld
    apt-get install -y git
    apt-get install -y libdate-manip-perl
    apt-get install -y libpam-cracklib
    apt-get install -y logwatch
    apt-get install -y nano
    apt-get install -y net-tools
    apt-get install -y openssh-server
    apt-get install -y openssl
    apt-get install -y p7zip
    apt-get install -y postgresql postgresql-contrib
    apt-get install -y rkhunter
    apt-get install -y rsyslog
    apt-get install -y ufw
    apt-get install -y unattended-upgrades
 
    # Updating again to make sure everything is up to date (Can't be too careful!)
    apt-get update
    apt-get upgrade -y
    apt-get --fix-broken install -y
    snap refresh
 
    # Uninstalling prohibited apps
    # Hacking tools
    apt-get remove -y aircrack-ng
    apt-get remove -y apache2
    apt-get remove -y apktool
    apt-get remove -y autopsy
    apt-get remove -y deluge
    apt-get remove -y dirb
    apt-get remove -y dsniff
    apt-get remove -y ettercap
    apt-get remove -y fcracklib
    apt-get remove -y ftp
    apt-get remove -y ftpscan
    apt-get remove -y httrack
    apt-get remove -y hydra
    apt-get remove -y john-the-ripper
    apt-get remove -y kismet
    apt-get remove -y linuxdcpp
    apt-get remove -y metasploit-framework
    apt-get remove -y nbtscan
    apt-get remove -y netcat
    apt-get remove -y nikto
    apt-get remove -y nmap
    apt-get remove -y ophcrack
    apt-get remove -y rfdump
    apt-get remove -y skipfish
    apt-get remove -y snort
    apt-get remove -y sqlmap
    apt-get remove -y wifite
    apt-get remove -y wireshark
    apt-get remove -y yersinia
    apt-get remove -y zenmap
    # Games
    apt-get remove -y aisleriot
    apt-get remove -y endless-sky
    apt-get remove -y freeciv
    apt-get remove -y gnome-mahjongg
    apt-get remove -y gnome-mines
    apt-get remove -y gnome-sudoku
    apt-get remove -y gnomine
    apt-get remove -y wesnoth
    # Insecure software
    apt-get remove -y ldap-utils
    apt-get remove -y manaplus
    apt-get remove -y nis
    apt-get remove -y rpcbind
    apt-get remove -y rsh-client
    apt-get remove -y rsh-server
    apt-get remove -y rsync
    apt-get remove -y talk
    apt-get remove -y telnet
    apt-get remove -y telnetd
    # Unnecessary bloatware
    apt-get remove -y apport
    apt-get remove -y atd
    apt-get remove -y autofs
    apt-get remove -y avahi-daemon
    apt-get remove -y avahi-utils
    apt-get remove -y bind9
    apt-get remove -y cups
    apt-get remove -y dovecot-imapd
    apt-get remove -y dovecot-pop3d
    apt-get remove -y iptables-persistent
    apt-get remove -y isc-dhcp-server
    apt-get remove -y nfs-common
    apt-get remove -y nfs-kernel-server
    apt-get remove -y nginx
    apt-get remove -y portmap
    apt-get remove -y python-zeitgeist
    apt-get remove -y rhythmbox-plugin-zeitgeist
    apt-get remove -y rpcbind
    apt-get remove -y slapd
    apt-get remove -y squid
    apt-get remove -y xserver-xorg*
    apt-get remove -y zeitgeist
    apt-get remove -y zeitgeist-core
    apt-get remove -y zeitgeist-datahub
 
    # Updating again to make sure everything is up to date (Can't be too careful!)
    apt-get update
    apt-get upgrade -y
    apt-get --fix-broken install -y
    apt-get autoremove -y
    snap refresh
   
    # Setting up auditd
    systemctl --now enable auditd
    augenrules --load
    echo "max_log_file_action = keep_logs" | tee -a /etc/audit/auditd.conf
 
    # Time Rules
    echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" | tee -a /etc/audit/rules.d/time.rules
    echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change" | tee -a /etc/audit/rules.d/time.rules
    echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" | tee -a /etc/audit/rules.d/time.rules
    echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" | tee -a /etc/audit/rules.d/time.rules
    echo "wa -k time-change" | tee -a /etc/audit/rules.d/time.rules
 
    # System Locale Rules
    echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" | tee -a /etc/audit/rules.d/system-locale.rules
    echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" | tee -a /etc/audit/rules.d/system-locale.rules
    echo "-w /etc/issue -p wa -k system-locale" | tee -a /etc/audit/rules.d/system-locale.rules
    echo "-w /etc/issue.net -p wa -k system-locale" | tee -a /etc/audit/rules.d/system-locale.rules
    echo "-w /etc/hosts -p wa -k system-locale" | tee -a /etc/audit/rules.d/system-locale.rules
    echo "-w /etc/network -p wa -k system-locale" | tee -a /etc/audit/rules.d/system-locale.rules
 
    # Identity Rules
    echo "-w /etc/group -p wa -k identity" | tee -a /etc/audit/rules.d/identity.rules
    echo "-w /etc/passwd -p wa -k identity" | tee -a /etc/audit/rules.d/identity.rules
    echo "-w /etc/gshadow -p wa -k identity" | tee -a /etc/audit/rules.d/identity.rules
    echo "-w /etc/shadow -p wa -k identity" | tee -a /etc/audit/rules.d/identity.rules
    echo "-w /etc/security/opasswd -p wa -k identity" | tee -a /etc/audit/rules.d/identity.rules
 
    # Login Rules
    echo "-w /var/log/faillog -p wa -k logins" | tee -a /etc/audit/rules.d/logins.rules
    echo "-w /var/log/lastlog -p wa -k logins" | tee -a /etc/audit/rules.d/logins.rules
    echo "-w /var/log/tallylog -p wa -k logins" | tee -a /etc/audit/rules.d/logins.rules
 
    # Permissions Rules
    echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" | tee -a /etc/audit/rules.d/permissions.rules
    echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" | tee -a /etc/audit/rules.d/permissions.rules
    echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" | tee -a /etc/audit/rules.d/permissions.rules
    echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" | tee -a /etc/audit/rules.d/permissions.rules
    echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" | tee -a /etc/audit/rules.d/permissions.rules
    echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" | tee -a /etc/audit/rules.d/permissions.rules
 
    # File Change Rules
    echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" | tee -a /etc/audit/rules.d/file-change.rules
    echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" | tee -a /etc/audit/rules.d/file-change.rules
 
    # Scope Rules
    echo "-w /etc/sudoers -p wa -k scope" | tee -a /etc/audit/rules.d/scope.rules
    echo "-w /etc/sudoers.d/ -p wa -k scope" | tee -a /etc/audit/rules.d/scope.rules
 
    # Rules
    echo "-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions" | tee -a /etc/audit/rules.d/sudo.rules
    echo "-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions" | tee -a /etc/audit/rules.d/sudo.rules
 
    # Module Rules
    echo "-w /sbin/insmod -p x -k modules" | tee -a /etc/audit/rules.d/modules.rules
    echo "-w /sbin/rmmod -p x -k modules" | tee -a /etc/audit/rules.d/modules.rules
    echo "-w /sbin/modprobe -p x -k modules" | tee -a /etc/audit/rules.d/modules.rules
    echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" | tee -a /etc/audit/rules.d/modules.rules
 
    # Reloading audit config
    auditctl -e 1 /etc/audit/rules.d/time.rules
    auditctl -e 1 /etc/audit/rules.d/system-locale.rules
    auditctl -e 1 /etc/audit/rules.d/identity.rules
    auditctl -e 1 /etc/audit/rules.d/logins.rules
    auditctl -e 1 /etc/audit/rules.d/permissions.rules
    auditctl -e 1 /etc/audit/rules.d/file-change.rules
    auditctl -e 1 /etc/audit/rules.d/scope.rules
    auditctl -e 1 /etc/audit/rules.d/sudo.rules
    auditctl -e 1 /etc/audit/rules.d/modules.rules

    # Reloading auditd
    systemctl restart auditd
    augenrules --load

    # Running chkrootkit
    sudo chkrootkit | sudo tee -a /scriptDump/RootKitInfo.txt

    # Making chkrootkit run daily
    sudo echo 'RUN_DAILY="true"' | sudo tee -a /etc/chkrootkit.conf

    # Getting sample configuration
    sudo cp /usr/local/etc/clamav/freshclam.conf.sample /usr/local/etc/clamav/freshclam.conf
    sudo cp /usr/local/etc/clamav/clamd.conf.sample /usr/local/etc/clamav/clamd.conf

    # Runs the Clam antivirus.
    clamscan -r --remove /

    # Starts firewalld
    systemctl enable firewalld
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload

    # Sets up logwatch
    mkdir /var/cache/logwatch
    cp /usr/share/logwatch/default.conf/logwatch.conf /etc/logwatch/conf/

    echo "Output = mail" | tee -a /etc/logwatch/conf/logwatch.conf
    echo "MailTo = me@mydomain.org" | tee -a /etc/logwatch/conf/logwatch.conf
    echo "MailFrom = logwatch@host1.mydomain.org" | tee -a /etc/logwatch/conf/logwatch.conf
    echo "Detail = Low" | tee -a /etc/logwatch/conf/logwatch.conf
    echo "Service = All" | tee -a /etc/logwatch/conf/logwatch.conf
    echo "Service = '-http'" | tee -a /etc/logwatch/conf/logwatch.conf
    echo "Service = '-eximstats'" | tee -a /etc/logwatch/conf/logwatch.conf

    logwatch --detail Low --range today

    # Sets up SSH
    sshd -t -f /etc/ssh/sshd_config
    echo "Banner /etc/issue.net" | tee -a /etc/ssh/sshd_config
    systemctl restart sshd.service

    # Editing sshd_config to set too many things to count.
    echo "PermitRootLogin no"         | tee -a /etc/ssh/sshd_config
    echo "PermitUserEnvironment no"   | tee -a /etc/ssh/sshd_config
    echo "PermitEmptyPasswords no"    | tee -a /etc/ssh/sshd_config
    echo "Protocol 2"                 | tee -a /etc/ssh/sshd_config
    echo "PrintLastLog no"            | tee -a /etc/ssh/sshd_config
    echo "PubkeyAuthentication yes"   | tee -a /etc/ssh/sshd_config
    echo "RSAAuthentication yes"      | tee -a /etc/ssh/sshd_config
    echo "LoginGraceTime 30"          | tee -a /etc/ssh/sshd_config
    echo "ClientAliveInterval 600"    | tee -a /etc/ssh/sshd_config
    echo "ClientAliveCountMax 1"      | tee -a /etc/ssh/sshd_config
    echo "UsePAM yes"                 | tee -a /etc/ssh/sshd_config
    echo "UsePrivilegeSeparation yes" | tee -a /etc/ssh/sshd_config
    echo "StrictModes yes"            | tee -a /etc/ssh/sshd_config
    echo "IgnoreUserKnownHosts yes"   | tee -a /etc/ssh/sshd_config
    echo "IgnoreRhosts yes"           | tee -a /etc/ssh/sshd_config
    echo "RhostsAuthentication no"    | tee -a /etc/ssh/sshd_config
    echo "RhostsRSAAuthentication no" | tee -a /etc/ssh/sshd_config
    echo "HostBasedAuthentication no" | tee -a /etc/ssh/sshd_config
    echo "AllowTcpForwarding no"      | tee -a /etc/ssh/sshd_config
    echo "X11Forwarding no"           | tee -a /etc/ssh/sshd_config
    echo "LogLevel VERBOSE"           | tee -a /etc/ssh/sshd_config
    echo "Port 2453"                  | tee -a /etc/ssh/sshd_config

    # Editing rkhunter permissions
    echo "UPDATE_MIRRORS=1" | tee -a "/etc/rkhunter.conf"
    echo "CRON_DAILY_RUN=true" | tee -a "/etc/rkhunter.conf"
    echo "ALLOW_SSH_ROOT_USER=no" | tee -a "/etc/rkhunter.conf"
    echo "ALOW_SSH_PROT_1=no" | tee -a "/etc/rkhunter.conf"
    echo "ALLOW_SYSLOG_REMOTE=no" | tee -a "/etc/rkhunter.conf"
    echo "USER_SYSLOG=authpriv.notice" | tee -a "/etc/rkhunter.conf"

    # Updating and running rkhunter
    rkhunter --update
    rkhunter --check

    # Running rkhunter daily (just moves a file into cron.daily)
    mv rkhunter /etc/cron.daily

    # Setting up firewall
    ufw allow in on lo
    ufw allow out on lo
    ufw deny in from 127.0.0.0/8
    ufw deny in from ::1
    ufw allow ssh
    ufw allow http
    ufw deny 23
    ufw default deny
    ufw --force enable

    # Enabling automatic updates and updating daily
    dpkg-reconfigure -plow unattended-upgrades
    
    ## Fixing System file permissions
    chmod 640 /etc/shadow
    chmod 644 /etc/passwd
    chmod 640 /var/log
    chmod 640 /var/log/syslog
    chown syslog /var/log/syslog
    chown root /var/log
    chgrp adm /var/log/syslog
    chmod 755 /bin
    chmod 755 /sbin
    chmod 755 /usr/bin
    chmod 755 /usr/sbin
    chmod 755 /usr/local/bin
    chmod 755 /usr/local/sbin
    
    # Editing /etc/login.defs to set a max passwd age(90), min passwd age(7), warn age(14), number of retries(3), and a login timeout(30).
    echo "PASS_MAX_DAYS 90" | tee -a "/etc/login.defs"
    echo "PASS_MIN_DAYS 7"  | tee -a "/etc/login.defs"
    echo "PASS_WARN_AGE 14" | tee -a "/etc/login.defs"
    echo "LOGIN_RETRIES 3"  | tee -a "/etc/login.defs"
    echo "LOGIN_TIMEOUT 30" | tee -a "/etc/login.defs"
 
    # Setting lockout policy
    echo "auth required pam_tally2.so deny=10 unlock_time=1800" | sudo tee -a "/etc/pam.d/common-auth"
 
    # Setting minimum password length and how many passwords to remember
    echo "auth required pam_unix.so minlen=8 remember=5" | sudo tee -a "/etc/pam.d/common-password"
 
    # I don't know what this does, but it helps
    echo "auth required pam_cracklib.so ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-" | sudo tee -a "/etc/pam.d/common-password"
 
    # Editing /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf to add 'allow-guest=false'. May cause an error.
    echo "allow-guest=false" | sudo tee -a "/usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf"
 
    # Forces user authentication for sudo.  I can't use editFile for this because I can't append it and Defaults appears many times.
    sed -i "9 a\Defaults env_reset, timestamp_timeout=0" /etc/sudoers
    sed -i "9 d" /etc/sudoers
 
    # Managing FTP permissions (Removing write commands and allowing ssl)
    echo "cmds_denied rmdir send rename put mput mdelete delete chmod" | sudo tee -a "/etc/vsftpd.conf"
    echo "ssl_enable=YES" | sudo tee -a "/etc/vsftpd"
 
    # Disabling SMTP
    sudo service sendmail stop
 
    # Enabling ASLR
    echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
    echo "kernel.randomize_va_space = 0" | sudo tee /etc/sysctl.d/01-disable-aslr.conf
 
    # Disabling unnecessary services
    # DNS Server
    echo DNSStubListener=no | tee -a /etc/systemd/resolved.conf;
    systemctl stop systemd-resolved;
    systemctl disable systemd-resolved
    # inetd
    echo inetd_enable=no | tee -a /etc/rc.conf
    # NFS Server
    systemctl stop nfs
 
    # Puts the cron jobs onto the desktop.  (Both user and root)
    for filename in /var/spool/cron/crontabs/*; do
        cat "$filename" | tee -a /var/output/cronjobs.txt
    done
    cat /etc/crontab | tee -a /var/output/cronjobs.txt
    # Use 'crontab -r' to remove unnecessary jobs.
 
    # Enabling cookie protection
    sysctl -w net.ipv4.tcp_syncookies=1
    # Disabling ipv6
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    # Disabling IP forwarding
    sysctl -w net.ipv4.ip_forward=0
    # Preventing IP Spoofing
    echo "nospoof on" | tee -a /etc/host.conf
 
    # Deleting prohibited files (This may delete files needed for the image, be careful!)
    find / -type f -name "*.mp3"   > audio.txt
    find / -type f -name "*.ac3"   > audio.txt
    find / -type f -name "*.aac"   > audio.txt
    find / -type f -name "*.aiff"  > audio.txt
    find / -type f -name "*.flac"  > audio.txt
    find / -type f -name "*.m4a"   > audio.txt
    find / -type f -name "*.m4p"   > audio.txt
    find / -type f -name "*.midi"  > audio.txt
    find / -type f -name "*.mp2"   > audio.txt
    find / -type f -name "*.m3u"   > audio.txt
    find / -type f -name "*.ogg"   > audio.txt
    find / -type f -name "*.vqf"   > audio.txt
    find / -type f -name "*.wav"   > audio.txt
    find / -type f -name "*.wma"   > vids.txt
    find / -type f -name "*.mp4"   > vids.txt
    find / -type f -name "*.avi"   > vids.txt
    find / -type f -name "*.mpeg4" > vids.txt
    find / -type f -name "*.gif"   > pics.txt
    find / -type f -name "*.png"   > pics.txt
    find / -type f -name "*.bmp"   > pics.txt
    find / -type f -name "*.jpg"   > pics.txt
    find / -type f -name "*.jpeg"  > pics.txt

    echo "Setting all passwords to SigmaCyberPatriot23!"
    for user in $(getent passwd | awk -F: '{print $1}')
    do
        echo "$user:SigmaCyberPatriot23!" | tee test.txt; sudo chpasswd < test.txt
    done
 
    # This creates users
    while true
    do
        echo "Enter the name of a user to add.  Type '0' to move on."
        read -r user
        if [ "$user" -eq 0 ]
            then break
        else
            useradd "$user" -m
        fi
    done
 
    # This creates groups
    while true
    do
        echo "Enter the name of a group to add.  Type '0' to move on."
        read -r group
        if [ "$group" -eq 0 ]
            then break
        else
            groupadd "$group" -m
        fi
    done
 
    # This adds users to existing groups
    while true
    do
        echo "Enter a group to add to.  Type '0' to move on."
        read -r group
        if [ "$group" -eq 0 ]
            then break
        else
            echo "Now enter a user to add to $group"
            read -r user
            usermod -aG "$group" "$user"
        fi
    done
 
    # This deletes users
    while true
    do
        echo "Enter the name of a user to delete.  Type '0' to move on."
        read -r user
        if [ "$user" -eq 0 ]
            then break
        else
            userdel "$user"
        fi
    done
 
    # This deletes groups
    while true
    do
        echo "Enter the name of a group to delete.  Type '0' to move on."
        read -r group
        if [ "$group" -eq 0 ]
            then break
        else
            groupdel "$group"
        fi
    done
 
    # These commands will remove admin rights from all users and then give them back to the users specified in the admins array.
    # Removing admin permissions
    for user in $(getent passwd | awk -F: '{if ($3 > 999 && $3 != 65534) print $1}')
    do
        usermod -G "$user" "$user"
    done
   
    # Giving back admin permissions
    while true
    do
        echo "Enter the name of a admin to add.  Type '0' to move on."
        read -r admin
        if [ "$admin" -eq 0 ]
            then break
        else
            usermod -aG "sudo" "$admin"
        fi
    done
 
    echo "Check /var/log/rkhunter.log for rootkits before exiting."
 
    read -rp "Press [Enter] to return to the menu."
    clear
    main
}
 
function managePorts {
    # Checks for open ports.
    touch pids.txt
    touch ports.txt
    netstat -tulpna | awk '{if ($7 != "-" && $7 != "" && $7 != "Address") print $7;}' | tee -a pids.txt   # Puts the process ids into a text file
    netstat -tulpna | awk '{if ($7 != "-" && $7 != "" && $4 != "Local") print $4;}'   | tee -a ports.txt  # Puts the ports into a text file
 
    touch finalPorts.txt
    while read -r -u 10 pid && read -r -u 11 port
    do
        printf "Port: %s, PID: %s" "$port" "$pid" | tee -a finalPorts.txt  # Puts an outline of each port and the pid/command using it.
    done 10<pids.txt 11<ports.txt
 
    # Removing unnecessary files.
    rm pids.txt
    rm ports.txt
   
    # Windows command is netstat -ano, in case that is ever helpful.
    while (true)
    do
        VAR10=0
        VAR11=""
        echo "What port do you want to close?"
        read -r VAR10
        ufw deny "$VAR10"
        echo "Do you want to close another port? [Y/n]"
        read -r VAR11
        if [ "$VAR11" != "Y" ] && [ "$VAR11" != "y" ]; then
            break
        fi
    done
 
    read -rp "Press [Enter] to return to the menu."
    clear
    main
}
 
# This function updates the properties for firefox
function firefoxPolicies {
    # Firefox is no longer used by CyberPatriot, but just in case...
    # Manages Firefox settings
    touch syspref.js

    echo 'pref("dom.serviceWorkers.enabled", false);' | tee syspref.js
    echo 'pref("dom.webnotifications.enabled", false);' | tee -a syspref.js
    echo 'pref("dom.enable_performance", true);' | tee -a syspref.js
    echo 'pref("dom.enable_resource_timing", false);' | tee -a syspref.js
    echo 'pref("dom.enable_timing", false);' | tee -a syspref.js
    echo 'pref("dom.webaudio.enabled", false);' | tee -a syspref.js
    echo 'pref("geo.enabled", false);' | tee -a syspref.js
    echo 'pref("geo.wifi.uri", "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%");' | tee -a syspref.js
    echo 'pref("geo.wifi.logging.enabled", false);' | tee -a syspref.js
    echo 'pref("dom.mozTCPSocket.enabled", false);' | tee -a syspref.js
    echo 'pref("dom.netinfo.enabled", false);' | tee -a syspref.js
    echo 'pref("dom.network.enabled", false);' | tee -a syspref.js
    echo 'pref("media.peerconnection.enabled", false);' | tee -a syspref.js
    echo 'pref("media.peerconnection.ice.no_host",  true);' | tee -a syspref.js
    echo 'pref("media.navigator.enabled", false);' | tee -a syspref.js
    echo 'pref("media.navigator.video.enabled", false);' | tee -a syspref.js
    echo 'pref("media.getusermedia.screensharing.enabled", false);' | tee -a syspref.js
    echo 'pref("media.getusermedia.audiocapture.enabled", false);' | tee -a syspref.js
    echo 'pref("dom.battery.enabled", false);' | tee -a syspref.js
    echo 'pref("dom.telephony.enabled", false);' | tee -a syspref.js
    echo 'pref("beacon.enabled", false);' | tee -a syspref.js
    echo 'pref("dom.event.clipboardevents.enabled", false);' | tee -a syspref.js
    echo 'pref("dom.allow_cut_copy", false);' | tee -a syspref.js
    echo 'pref("media.webspeech.recognition.enable", false);' | tee -a syspref.js
    echo 'pref("media.webspeech.synth.enabled", false);' | tee -a syspref.js
    echo 'pref("device.sensors.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.send_pings", false);' | tee -a syspref.js
    echo 'pref("browser.send_pings.require_same_host", true);' | tee -a syspref.js
    echo 'pref("dom.gamepad.enabled", false);' | tee -a syspref.js
    echo 'pref("dom.vr.enabled", false);' | tee -a syspref.js
    echo 'pref("dom.vibrator.enabled", false);' | tee -a syspref.js
    echo 'pref("dom.archivereader.enabled", false);' | tee -a syspref.js
    echo 'pref("webgl.disabled", true);' | tee -a syspref.js
    echo 'pref("webgl.min_capability_mode", true);' | tee -a syspref.js
    echo 'pref("webgl.disable-extensions", true);' | tee -a syspref.js
    echo 'pref("webgl.disable-fail-if-major-performance-caveat", true);' | tee -a syspref.js
    echo 'pref("webgl.enable-debug-renderer-info", false);' | tee -a syspref.js
    echo 'pref("dom.maxHardwareConcurrency", 2);' | tee -a syspref.js
    echo 'pref("javascript.options.wasm", false);' | tee -a syspref.js
    echo 'pref("camera.control.face_detection.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.search.countryCode", "US");' | tee -a syspref.js
    echo 'pref("browser.search.region", "US");' | tee -a syspref.js
    echo 'pref("browser.search.geoip.url", "");' | tee -a syspref.js
    echo 'pref("intl.accept_languages", "en-US, en");' | tee -a syspref.js
    echo 'pref("intl.locale.matchOS", false);' | tee -a syspref.js
    echo 'pref("browser.search.geoSpecificDefaults", false);' | tee -a syspref.js
    echo 'pref("clipboard.autocopy", false);' | tee -a syspref.js
    echo 'pref("javascript.use_us_english_locale", true);' | tee -a syspref.js
    echo 'pref("keyword.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.urlbar.trimURLs", false);' | tee -a syspref.js
    echo 'pref("browser.fixup.alternate.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.fixup.hide_pass", true);' | tee -a syspref.js
    echo 'pref("network.proxy.socks_remote_dns", true);' | tee -a syspref.js
    echo 'pref("network.manage-offline-status", false);' | tee -a syspref.js
    echo 'pref("security.mixed_content.block_active_content", true);' | tee -a syspref.js
    echo 'pref("security.mixed_content.block_display_content", true);' | tee -a syspref.js
    echo 'pref("network.jar.open-unsafe-types", false);' | tee -a syspref.js
    echo 'pref("security.xpconnect.plugin.unrestricted", false);' | tee -a syspref.js
    echo 'pref("security.fileuri.strict_origin_policy", true);' | tee -a syspref.js
    echo 'pref("browser.urlbar.filter.javascript", true);' | tee -a syspref.js
    echo 'pref("javascript.options.asmjs", false);' | tee -a syspref.js
    echo 'pref("gfx.font_rendering.opentype_svg.enabled", false);' | tee -a syspref.js
    echo 'pref("media.video_stats.enabled", false);' | tee -a syspref.js
    echo 'pref("general.buildID.override", "20100101");' | tee -a syspref.js
    echo 'pref("browser.startup.homepage_override.buildID", "20100101");' | tee -a syspref.js
    echo 'pref("browser.display.use_document_fonts", 0);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.warn-external-default", true);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.external.http", false);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.external.https", false);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.external.javascript", false);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.external.moz-extension", false);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.external.ftp", false);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.external.file", false);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.external.about", false);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.external.chrome", false);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.external.blob", false);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.external.data", false);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.expose-all", false);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.expose.http", true);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.expose.https", true);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.expose.javascript", true);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.expose.moz-extension", true);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.expose.ftp", true);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.expose.file", true);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.expose.about", true);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.expose.chrome", true);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.expose.blob", true);' | tee -a syspref.js
    echo 'pref("network.protocol-handler.expose.data", true);' | tee -a syspref.js
    echo 'pref("security.dialog_enable_delay", 1000);' | tee -a syspref.js
    echo 'pref("extensions.getAddons.cache.enabled", false);' | tee -a syspref.js
    echo 'pref("lightweightThemes.update.enabled", false);' | tee -a syspref.js
    echo 'pref("plugin.state.flash", 0);' | tee -a syspref.js
    echo 'pref("plugin.state.java", 0);' | tee -a syspref.js
    echo 'pref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled", false);' | tee -a syspref.js
    echo 'pref("dom.ipc.plugins.reportCrashURL", false);' | tee -a syspref.js
    echo 'pref("browser.safebrowsing.blockedURIs.enabled", true);' | tee -a syspref.js
    echo 'pref("plugin.state.libgnome-shell-browser-plugin", 0);' | tee -a syspref.js
    echo 'pref("plugins.click_to_play", true);' | tee -a syspref.js
    echo 'pref("extensions.update.enabled", true);' | tee -a syspref.js
    echo 'pref("extensions.blocklist.enabled", true);' | tee -a syspref.js
    echo 'pref("services.blocklist.update_enabled", true);' | tee -a syspref.js
    echo 'pref("extensions.blocklist.url", "https://blocklist.addons.mozilla.org/blocklist/3/%APP_ID%/%APP_VERSION%/");' | tee -a syspref.js
    echo 'pref("extensions.systemAddon.update.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr", false);' | tee -a syspref.js
    echo 'pref("devtools.webide.enabled", false);' | tee -a syspref.js
    echo 'pref("devtools.webide.autoinstallADBHelper", false);' | tee -a syspref.js
    echo 'pref("devtools.webide.autoinstallFxdtAdapters", false);' | tee -a syspref.js
    echo 'pref("devtools.debugger.remote-enabled", false);' | tee -a syspref.js
    echo 'pref("devtools.chrome.enabled", false);' | tee -a syspref.js
    echo 'pref("devtools.debugger.force-local", true);' | tee -a syspref.js
    echo 'pref("toolkit.telemetry.enabled", false);' | tee -a syspref.js
    echo 'pref("toolkit.telemetry.unified", false);' | tee -a syspref.js
    echo 'pref("toolkit.telemetry.archive.enabled", false);' | tee -a syspref.js
    echo 'pref("experiments.supported", false);' | tee -a syspref.js
    echo 'pref("experiments.enabled", false);' | tee -a syspref.js
    echo 'pref("experiments.manifest.uri", "");' | tee -a syspref.js
    echo 'pref("network.allow-experiments", false);' | tee -a syspref.js
    echo 'pref("breakpad.reportURL", "");' | tee -a syspref.js
    echo 'pref("browser.tabs.crashReporting.sendReport", false);' | tee -a syspref.js
    echo 'pref("browser.crashReports.unsubmittedCheck.enabled", false);' | tee -a syspref.js
    echo 'pref("dom.flyweb.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.uitour.enabled", false);' | tee -a syspref.js
    echo 'pref("privacy.trackingprotection.enabled", true);' | tee -a syspref.js
    echo 'pref("privacy.trackingprotection.pbmode.enabled", true);' | tee -a syspref.js
    echo 'pref("privacy.userContext.enabled", true);' | tee -a syspref.js
    echo 'pref("privacy.resistFingerprinting", true);' | tee -a syspref.js
    echo 'pref("privacy.resistFingerprinting.block_mozAddonManager", true);' | tee -a syspref.js
    echo 'pref("extensions.webextensions.restrictedDomains", "");' | tee -a syspref.js
    echo 'pref("browser.startup.blankWindow", false);' | tee -a syspref.js
    echo 'pref("pdfjs.disabled", true);' | tee -a syspref.js
    echo 'pref("datareporting.healthreport.uploadEnabled", false);' | tee -a syspref.js
    echo 'pref("datareporting.healthreport.service.enabled", false);' | tee -a syspref.js
    echo 'pref("datareporting.policy.dataSubmissionEnabled", false);' | tee -a syspref.js
    echo 'pref("browser.discovery.enabled", false);' | tee -a syspref.js
    echo 'pref("app.normandy.enabled", false);' | tee -a syspref.js
    echo 'pref("app.normandy.api_url", "");' | tee -a syspref.js
    echo 'pref("extensions.shield-recipe-client.enabled", false);' | tee -a syspref.js
    echo 'pref("app.shield.optoutstudies.enabled", false);' | tee -a syspref.js
    echo 'pref("loop.logDomains", false);' | tee -a syspref.js
    echo 'pref("app.update.enabled", true);' | tee -a syspref.js
    echo 'pref("browser.safebrowsing.phishing.enabled", true);' | tee -a syspref.js
    echo 'pref("browser.safebrowsing.malware.enabled", true);' | tee -a syspref.js
    echo 'pref("browser.safebrowsing.downloads.remote.enabled", true);' | tee -a syspref.js
    echo 'pref("browser.pocket.enabled", false);' | tee -a syspref.js
    echo 'pref("extensions.pocket.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);' | tee -a syspref.js
    echo 'pref("network.prefetch-next", false);' | tee -a syspref.js
    echo 'pref("network.dns.disablePrefetch", true);' | tee -a syspref.js
    echo 'pref("network.dns.disablePrefetchFromHTTPS", true);' | tee -a syspref.js
    echo 'pref("network.predictor.enabled", false);' | tee -a syspref.js
    echo 'pref("network.dns.blockDotOnion", true);' | tee -a syspref.js
    echo 'pref("browser.search.suggest.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.urlbar.suggest.searches", false);' | tee -a syspref.js
    echo 'pref("browser.urlbar.suggest.history", false);' | tee -a syspref.js
    echo 'pref("browser.urlbar.groupLabels.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.casting.enabled", false);' | tee -a syspref.js
    echo 'pref("media.gmp-gmpopenh264.enabled", false);' | tee -a syspref.js
    echo 'pref("media.gmp-manager.url", "");' | tee -a syspref.js
    echo 'pref("network.http.speculative-parallel-limit", 0);' | tee -a syspref.js
    echo 'pref("browser.aboutHomeSnippets.updateUrl", "");' | tee -a syspref.js
    echo 'pref("browser.search.update", false);' | tee -a syspref.js
    echo 'pref("network.captive-portal-service.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.topsites.contile.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.newtabpage.activity-stream.feeds.topsites", false);' | tee -a syspref.js
    echo 'pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);' | tee -a syspref.js
    echo 'pref("network.negotiate-auth.allow-insecure-ntlm-v1", false);' | tee -a syspref.js
    echo 'pref("security.csp.experimentalEnabled", true);' | tee -a syspref.js
    echo 'pref("security.csp.enable", true);' | tee -a syspref.js
    echo 'pref("security.sri.enable", true);' | tee -a syspref.js
    echo 'pref("network.http.referer.XOriginPolicy", 2);' | tee -a syspref.js
    echo 'pref("network.cookie.cookieBehavior", 1);' | tee -a syspref.js
    echo 'pref("privacy.firstparty.isolate", true);' | tee -a syspref.js
    echo 'pref("network.cookie.thirdparty.sessionOnly", true);' | tee -a syspref.js
    echo 'pref("browser.privatebrowsing.autostart", true);' | tee -a syspref.js
    echo 'pref("browser.cache.offline.enable", false);' | tee -a syspref.js
    echo 'pref("privacy.sanitize.sanitizeOnShutdown", true);' | tee -a syspref.js
    echo 'pref("privacy.clearOnShutdown.cache", true);' | tee -a syspref.js
    echo 'pref("privacy.clearOnShutdown.cookies", true);' | tee -a syspref.js
    echo 'pref("privacy.clearOnShutdown.downloads", true);' | tee -a syspref.js
    echo 'pref("privacy.clearOnShutdown.formdata", true);' | tee -a syspref.js
    echo 'pref("privacy.clearOnShutdown.history", true);' | tee -a syspref.js
    echo 'pref("privacy.clearOnShutdown.offlineApps", true);' | tee -a syspref.js
    echo 'pref("privacy.clearOnShutdown.sessions", true);' | tee -a syspref.js
    echo 'pref("privacy.clearOnShutdown.openWindows", true);' | tee -a syspref.js
    echo 'pref("privacy.sanitize.timeSpan", 0);' | tee -a syspref.js
    echo 'pref("privacy.cpd.offlineApps", true);' | tee -a syspref.js
    echo 'pref("privacy.cpd.cache", true);' | tee -a syspref.js
    echo 'pref("privacy.cpd.cookies", true);' | tee -a syspref.js
    echo 'pref("privacy.cpd.downloads", true);' | tee -a syspref.js
    echo 'pref("privacy.cpd.formdata", true);' | tee -a syspref.js
    echo 'pref("privacy.cpd.history", true);' | tee -a syspref.js
    echo 'pref("privacy.cpd.sessions", true);' | tee -a syspref.js
    echo 'pref("places.history.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.cache.disk.enable", false);' | tee -a syspref.js
    echo 'pref("browser.cache.disk_cache_ssl", false);' | tee -a syspref.js
    echo 'pref("browser.download.manager.retention", 0);' | tee -a syspref.js
    echo 'pref("signon.rememberSignons", false);' | tee -a syspref.js
    echo 'pref("browser.formfill.enable", false);' | tee -a syspref.js
    echo 'pref("network.cookie.lifetimePolicy", 2);' | tee -a syspref.js
    echo 'pref("signon.autofillForms", false);' | tee -a syspref.js
    echo 'pref("signon.formlessCapture.enabled", false);' | tee -a syspref.js
    echo 'pref("signon.autofillForms.http", false);' | tee -a syspref.js
    echo 'pref("security.insecure_field_warning.contextual.enabled", true);' | tee -a syspref.js
    echo 'pref("browser.formfill.expire_days", 0);' | tee -a syspref.js
    echo 'pref("browser.sessionstore.privacy_level", 2);' | tee -a syspref.js
    echo 'pref("browser.helperApps.deleteTempFileOnExit", true);' | tee -a syspref.js
    echo 'pref("browser.pagethumbnails.capturing_disabled", true);' | tee -a syspref.js
    echo 'pref("browser.shell.shortcutFavicons", false);' | tee -a syspref.js
    echo 'pref("browser.bookmarks.max_backups", 0);' | tee -a syspref.js
    echo 'pref("browser.chrome.site_icons", false);' | tee -a syspref.js
    echo 'pref("security.insecure_password.ui.enabled", true);' | tee -a syspref.js
    echo 'pref("browser.download.folderList", 2);' | tee -a syspref.js
    echo 'pref("browser.download.useDownloadDir", false);' | tee -a syspref.js
    echo 'pref("browser.newtabpage.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.newtab.url", "about:blank");' | tee -a syspref.js
    echo 'pref("browser.newtabpage.activity-stream.feeds.snippets", false);' | tee -a syspref.js
    echo 'pref("browser.newtabpage.activity-stream.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.newtabpage.enhanced", false);' | tee -a syspref.js
    echo 'pref("browser.newtab.preload", false);' | tee -a syspref.js
    echo 'pref("browser.newtabpage.directory.ping", "");' | tee -a syspref.js
    echo 'pref("browser.newtabpage.directory.source", "data:text/plain,{}");' | tee -a syspref.js
    echo 'pref("browser.vpn_promo.enabled", false);' | tee -a syspref.js
    echo 'pref("plugins.update.notifyUser", true);' | tee -a syspref.js
    echo 'pref("network.IDN_show_punycode", true);' | tee -a syspref.js
    echo 'pref("browser.urlbar.autoFill", false);' | tee -a syspref.js
    echo 'pref("browser.urlbar.autoFill.typed", false);' | tee -a syspref.js
    echo 'pref("layout.css.visited_links_enabled", false);' | tee -a syspref.js
    echo 'pref("browser.urlbar.autocomplete.enabled", false);' | tee -a syspref.js
    echo 'pref("browser.shell.checkDefaultBrowser", false);' | tee -a syspref.js
    echo 'pref("security.ask_for_password", 2);' | tee -a syspref.js
    echo 'pref("security.password_lifetime", 1);' | tee -a syspref.js
    echo 'pref("browser.offline-apps.notify", true);' | tee -a syspref.js
    echo 'pref("dom.security.https_only_mode", true);' | tee -a syspref.js
    echo 'pref("network.stricttransportsecurity.preloadlist", true);' | tee -a syspref.js
    echo 'pref("security.OCSP.enabled", 1);' | tee -a syspref.js
    echo 'pref("security.ssl.enable_ocsp_stapling", true);' | tee -a syspref.js
    echo 'pref("security.ssl.enable_ocsp_must_staple", true);' | tee -a syspref.js
    echo 'pref("security.OCSP.require", true);' | tee -a syspref.js
    echo 'pref("security.ssl.disable_session_identifiers", true);' | tee -a syspref.js
    echo 'pref("security.tls.version.min", 3);' | tee -a syspref.js
    echo 'pref("security.tls.version.max", 4);' | tee -a syspref.js
    echo 'pref("security.tls.version.fallback-limit", 4);' | tee -a syspref.js
    echo 'pref("security.cert_pinning.enforcement_level", 2);' | tee -a syspref.js
    echo 'pref("security.pki.sha1_enforcement_level", 1);' | tee -a syspref.js
    echo 'pref("security.ssl.treat_unsafe_negotiation_as_broken", true);' | tee -a syspref.js
    echo 'pref("security.ssl.errorReporting.automatic", false);' | tee -a syspref.js
    echo 'pref("browser.ssl_override_behavior", 1);' | tee -a syspref.js
    echo 'pref("network.security.esni.enabled", true);' | tee -a syspref.js
    echo 'pref("security.ssl3.rsa_null_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.rsa_null_md5", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdhe_rsa_null_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdhe_ecdsa_null_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdh_rsa_null_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdh_ecdsa_null_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.rsa_seed_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.rsa_rc4_40_md5", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.rsa_rc2_40_md5", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.rsa_1024_rc4_56_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.rsa_camellia_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdhe_rsa_aes_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdhe_ecdsa_aes_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdh_rsa_aes_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdh_ecdsa_aes_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.dhe_rsa_camellia_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.dhe_rsa_aes_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdh_ecdsa_rc4_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdh_rsa_rc4_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdhe_ecdsa_rc4_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdhe_rsa_rc4_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.rsa_rc4_128_md5", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.rsa_rc4_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.tls.unrestricted_rc4_fallback", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.dhe_dss_des_ede3_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.dhe_rsa_des_ede3_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdh_ecdsa_des_ede3_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdh_rsa_des_ede3_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdhe_ecdsa_des_ede3_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdhe_rsa_des_ede3_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.rsa_des_ede3_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.rsa_fips_des_ede3_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdh_rsa_aes_256_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdh_ecdsa_aes_256_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.rsa_camellia_256_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256", true);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdhe_rsa_aes_128_gcm_sha256", true);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdhe_ecdsa_chacha20_poly1305_sha256", true);' | tee -a syspref.js
    echo 'pref("security.ssl3.ecdhe_rsa_chacha20_poly1305_sha256", true);' | tee -a syspref.js
    echo 'pref("security.ssl3.dhe_rsa_camellia_256_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.dhe_rsa_aes_256_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.dhe_dss_aes_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.dhe_dss_aes_256_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.dhe_dss_camellia_128_sha", false);' | tee -a syspref.js
    echo 'pref("security.ssl3.dhe_dss_camellia_256_sha", false);' | tee -a syspref.js
    echo 'pref("browser.safebrowsing.downloads.enabled", true);' | tee -a syspref.js
    echo 'pref("browser.safebrowsing.downloads.remote.block_dangerous", true);' | tee -a syspref.js
    echo 'pref("browser.safebrowsing.downloads.remote.block_dangerous", true);' | tee -a syspref.js
    echo 'pref("browser.safebrowsing.downloads.remote.block_dangerous_host", true);' | tee -a syspref.js
    echo 'pref("browser.safebrowsing.downloads.remote.block_potentially_unwanted", true);' | tee -a syspref.js
    echo 'pref("browser.safebrowsing.downloads.remote.block_uncommon", true);' | tee -a syspref.js
    echo 'pref("dom.disable_during_load", true);' | tee -a syspref.js
    echo 'pref("dom.block_multiple_popups", true);' | tee -a syspref.js
    echo 'pref("dom.block_download_insecure", true);' | tee -a syspref.js
    echo 'pref("dom.allow_scripts_to_close_windows", false);' | tee -a syspref.js
    echo 'pref("media.autoplay.block-webaudio", true);' | tee -a syspref.js
    echo 'pref("media.block-autoplay-until-in-foreground", true);' | tee -a syspref.js
    echo 'pref("plugins.flashBlock.enabled", true);' | tee -a syspref.js
    echo 'pref("privacy.socialtracking.block_cookies.enabled", true);' | tee -a syspref.js
    echo 'pref("toolkit.telemetry.reportingpolicy.firstRun", false);' | tee -a syspref.js

    mv ./syspref.js /etc/firefox/syspref.js
 
    read -rp "Press [Enter] to return to the menu."
    clear
    main
}

# This function prints a small version of the checklist with a few links.
function checklist {
 
    printf "Checklist\n"
    printf "    1) Install and run ClamAV\n"
    printf "    2) Install and start ufw\n"
    printf "    3) Update apps\n"
    printf "    4) Read readme, there will definitely be something in there for points\n"
    printf "    5) Check past checklists (Here's one!).\n"
    printf "    6) Help teamates.\n"
    printf "    7) Get teamates to help you.\n"
    printf "    8) Win!!!\n\n"
 
    read -rp "Press [Enter] to return to the menu."
    clear
    main
}

clear
main
