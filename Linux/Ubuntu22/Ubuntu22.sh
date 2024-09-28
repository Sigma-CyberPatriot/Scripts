#!/bin/bash

# To get this script to work, run "chmod +x ./Ubuntu22.sh"
# To find all apt apps installed, run "apt list --installed"
# Please run this script as root.
# Fun fact: The text editor app on ubuntu can be run from command line with "gedit"

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
    printf "    3) View checklist                                                                                                   \n"
    printf "    4) Exit Program                                                                                                     \n"
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
        then checklist;
    elif [ "$answer" -eq 4 ]
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
    #echo "nospoof on" | sudo tee -a /etc/host.conf
    #echo "order bind,hosts" | sudo tee -a /etc/host.conf
    #ip link set dev promisc off

    # Installing apt-get

    # Getting apt version, OS name, and the codename of the OS
    APT_VERS=$(apt -v | awk '{print $2}')
    OS=$(awk -F= '{if ($1 == "ID") print $2}' < /etc/os-release)
    CODENAME=$(awk -F= '{if ($1 == "VERSION_CODENAME") print $2}' < /etc/os-release)

    # Installing apt
    wget "http://us.archive.ubuntu.com/ubuntu/pool/main/a/apt/libapt-pkg6.0_" + "$APT_VERS" + "_amd64.deb" -O libapt.deb
    wget "http://us.archive.ubuntu.com/ubuntu/pool/main/a/apt/apt_" + "$APT_VERS" + "_amd64.deb" -O apt.deb
    wget "http://us.archive.ubuntu.com/ubuntu/pool/main/a/apt/apt-utils_" + "$APT_VERS" + "_amd64.deb" -O apt-utils.deb
    dpkg -Ri .

    # Editing /etc/apt/sources.list
    if [ "$OS" = "debian" ]; then
        echo "deb http://deb.debian.org/debian $CODENAME contrib main non-free non-free-firmware" | sudo tee /etc/apt/sources.list
        echo "deb http://deb.debian.org/debian $CODENAME-backports contrib main non-free non-free-firmware" | sudo tee -a /etc/apt/sources.list
        echo "deb http://deb.debian.org/debian $CODENAME-updates contrib main non-free non-free-firmware" | sudo tee -a /etc/apt/sources.list
        echo "deb http://security.debian.org/debian-security $CODENAME-security main non-free updates" | sudo tee -a /etc/apt/sources.list
    elif [ "$OS" = "ubuntu" ]; then
        echo "deb http://archive.ubuntu.com/ubuntu $CODENAME main multiverse restricted universe" | sudo tee /etc/apt/sources.list
        echo "deb http://archive.ubuntu.com/ubuntu $CODENAME-backports main multiverse restricted universe" | sudo tee -a /etc/apt/sources.list
        echo "deb http://archive.ubuntu.com/ubuntu $CODENAME-security main multiverse restricted universe" | sudo tee -a /etc/apt/sources.list
        echo "deb http://archive.ubuntu.com/ubuntu $CODENAME-updates main multiverse restricted universe" | sudo tee -a /etc/apt/sources.list
    fi

    # Making installs require secure ssl connection
    apt-get install -y wget ca-certificates
    wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -
    echo "deb http://apt.postgresql.org/pub/repos/apt/ $CODENAME-pgdg main" | sudo tee -a /etc/apt/sources.list.d/pgdg.list

    # Updating all apps (snaps included)
    apt-get update
    apt-get upgrade -y
    snap refresh

    # Installing apps
    apt-get install -y auditd
    apt-get install -y chkrootkit
    apt-get install -y cron
    apt-get install -y firewalld
    apt-get install -y libdate-manip-perl
    apt-get install -y libpam-cracklib
    apt-get install -y logwatch
    apt-get install -y nano
    apt-get install -y net-tools
    apt-get install -y openssh-server
    apt-get install -y openssl
    apt-get install -y p7zip
    apt-get install -y postgresql
    apt-get install -y postgresql-contrib
    apt-get install -y rkhunter
    apt-get install -y rsyslog
    apt-get install -y ufw

    # Updating again to make sure everything is up to date (Can't be too careful!)
    apt-get update
    apt-get upgrade -y
    apt-get --fix-broken install -y
    snap refresh

    # Uninstalling prohibited apps
    # Hacking tools
    apt-get purge -y aircrack-ng
    apt-get purge -y apktool
    apt-get purge -y autopsy
    apt-get purge -y deluge
    apt-get purge -y dirb
    apt-get purge -y dirbuster
    apt-get purge -y dsniff
    apt-get purge -y ettercap
    apt-get purge -y fcracklib
    apt-get purge -y fcrackzip
    apt-get purge -y freeciv
    apt-get purge -y Frostwire
    apt-get purge -y ftp
    apt-get purge -y ftpscan
    apt-get purge -y gobuster
    apt-get purge -y hashcat
    apt-get purge -y httrack
    apt-get purge -y hydra
    apt-get purge -y john
    apt-get purge -y kismet
    apt-get purge -y knocker
    apt-get purge -y linuxdcpp
    apt-get purge -y medusa
    apt-get purge -y metasploit-framework
    apt-get purge -y minetest
    apt-get purge -y nbtscan
    apt-get purge -y ncrack
    apt-get purge -y netcat
    apt-get purge -y nikto
    apt-get purge -y nmap
    apt-get purge -y ophcrack
    apt-get purge -y rfdump
    apt-get purge -y skipfish
    apt-get purge -y smbmap
    apt-get purge -y snort
    apt-get purge -y sqlmap
    apt-get purge -y tshark
    apt-get purge -y vuze
    apt-get purge -y wfuzz
    apt-get purge -y wifite
    apt-get purge -y wireshark
    apt-get purge -y yersinia
    apt-get purge -y zenmap
    # Games
    apt-get purge -y aisleriot
    apt-get purge -y endless-sky
    apt-get purge -y freeciv
    apt-get purge -y goldeneye
    apt-get purge -y gameconqueror
    apt-get purge -y gnome-mahjongg
    apt-get purge -y gnome-mines
    apt-get purge -y gnome-sudoku
    apt-get purge -y gnomine
    apt-get purge -y wesnoth
    # Insecure software
    apt-get purge -y ldap-utils
    apt-get purge -y manaplus
    apt-get purge -y nis
    apt-get purge -y rpcbind
    apt-get purge -y rsh-client
    apt-get purge -y rsh-server
    apt-get purge -y rsync
    apt-get purge -y talk
    apt-get purge -y telnet
    apt-get purge -y telnetd
    # Unnecessary bloatware
    apt-get purge -y apport
    apt-get purge -y atd
    apt-get purge -y autofs
    apt-get purge -y avahi-daemon
    apt-get purge -y avahi-utils
    apt-get purge -y bind9
    apt-get purge -y cups
    apt-get purge -y doona
    apt-get purge -y dovecot-imapd
    apt-get purge -y dovecot-pop3d
    apt-get purge -y iptables-persistent
    apt-get purge -y isc-dhcp-server
    apt-get purge -y nfs-common
    apt-get purge -y nfs-kernel-server
    apt-get purge -y nginx
    apt-get purge -y portmap
    apt-get purge -y proxychains
    apt-get purge -y python-zeitgeist
    apt-get purge -y rhythmbox-plugin-zeitgeist
    apt-get purge -y rpcbind
    apt-get purge -y slapd
    apt-get purge -y squidclient
    apt-get purge -y squid-cgi
    apt-get purge -y xprobe
    apt-get purge -y xserver-xorg*
    apt-get purge -y zeitgeist
    apt-get purge -y zeitgeist-core
    apt-get purge -y zeitgeist-datahub
    apt-get purge -y nmapsi4
    apt-get purge -y pumpa
    apt-get purge -y amule
    apt-get purge -y zangband
    apt-get purge -y fcrackzip
    apt-get purge -y themole
    apt-get purge -y SNMP
    apt-get purge -y packit
    apt-get purge -y pompem

    # Updating again to make sure everything is up to date (Can't be too careful!)
    apt-get update
    apt-get upgrade -y
    apt-get --fix-broken install -y
    apt-get autopurge -y
    snap refresh

    # Setting up auditd
    systemctl --now enable auditd
    augenrules --load
    echo "max_log_file_action = keep_logs" | sudo tee -a /etc/audit/auditd.conf

    # Time Rules
    echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" | sudo tee -a /etc/audit/rules.d/time.rules
    echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change" | sudo tee -a /etc/audit/rules.d/time.rules
    echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" | sudo tee -a /etc/audit/rules.d/time.rules
    echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" | sudo tee -a /etc/audit/rules.d/time.rules
    echo "wa -k time-change" | sudo tee -a /etc/audit/rules.d/time.rules

    # System Locale Rules
    echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" | sudo tee -a /etc/audit/rules.d/system-locale.rules
    echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" | sudo tee -a /etc/audit/rules.d/system-locale.rules
    echo "-w /etc/issue -p wa -k system-locale" | sudo tee -a /etc/audit/rules.d/system-locale.rules
    echo "-w /etc/issue.net -p wa -k system-locale" | sudo tee -a /etc/audit/rules.d/system-locale.rules
    echo "-w /etc/hosts -p wa -k system-locale" | sudo tee -a /etc/audit/rules.d/system-locale.rules
    echo "-w /etc/network -p wa -k system-locale" | sudo tee -a /etc/audit/rules.d/system-locale.rules

    # Identity Rules
    echo "-w /etc/group -p wa -k identity" | sudo tee -a /etc/audit/rules.d/identity.rules
    echo "-w /etc/passwd -p wa -k identity" | sudo tee -a /etc/audit/rules.d/identity.rules
    echo "-w /etc/gshadow -p wa -k identity" | sudo tee -a /etc/audit/rules.d/identity.rules
    echo "-w /etc/shadow -p wa -k identity" | sudo tee -a /etc/audit/rules.d/identity.rules
    echo "-w /etc/security/opasswd -p wa -k identity" | sudo tee -a /etc/audit/rules.d/identity.rules

    # Login Rules
    echo "-w /var/log/faillog -p wa -k logins" | sudo tee -a /etc/audit/rules.d/logins.rules
    echo "-w /var/log/lastlog -p wa -k logins" | sudo tee -a /etc/audit/rules.d/logins.rules
    echo "-w /var/log/tallylog -p wa -k logins" | sudo tee -a /etc/audit/rules.d/logins.rules

    # Permissions Rules
    echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" | sudo tee -a /etc/audit/rules.d/permissions.rules
    echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" | sudo tee -a /etc/audit/rules.d/permissions.rules
    echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" | sudo tee -a /etc/audit/rules.d/permissions.rules
    echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" | sudo tee -a /etc/audit/rules.d/permissions.rules
    echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" | sudo tee -a /etc/audit/rules.d/permissions.rules
    echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" | sudo tee -a /etc/audit/rules.d/permissions.rules

    # File Change Rules
    echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" | sudo tee -a /etc/audit/rules.d/file-change.rules
    echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" | sudo tee -a /etc/audit/rules.d/file-change.rules

    # Scope Rules
    echo "-w /etc/sudoers -p wa -k scope" | sudo tee -a /etc/audit/rules.d/scope.rules
    echo "-w /etc/sudoers.d/ -p wa -k scope" | sudo tee -a /etc/audit/rules.d/scope.rules

    # Rules
    echo "-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions" | sudo tee -a /etc/audit/rules.d/sudo.rules
    echo "-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions" | sudo tee -a /etc/audit/rules.d/sudo.rules

    # Module Rules
    echo "-w /sbin/insmod -p x -k modules" | sudo tee -a /etc/audit/rules.d/modules.rules
    echo "-w /sbin/rmmod -p x -k modules" | sudo tee -a /etc/audit/rules.d/modules.rules
    echo "-w /sbin/modprobe -p x -k modules" | sudo tee -a /etc/audit/rules.d/modules.rules
    echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" | sudo tee -a /etc/audit/rules.d/modules.rules

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
    sudo chkrootkit | sudo tee -a RootKitInfo.txt

    # Making chkrootkit run daily
    sudo echo 'RUN_DAILY="true"' | sudo tee -a /etc/chkrootkit.conf

    # Starts firewalld
    systemctl enable firewalld
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload

    # Sets up logwatch
    mkdir /var/cache/logwatch
    cp /usr/share/logwatch/default.conf/logwatch.conf /etc/logwatch/conf/

    echo "Output = mail" | sudo tee -a /etc/logwatch/conf/logwatch.conf
    echo "MailTo = me@mydomain.org" | sudo tee -a /etc/logwatch/conf/logwatch.conf
    echo "MailFrom = logwatch@host1.mydomain.org" | sudo tee -a /etc/logwatch/conf/logwatch.conf
    echo "Detail = Low" | sudo tee -a /etc/logwatch/conf/logwatch.conf
    echo "Service = All" | sudo tee -a /etc/logwatch/conf/logwatch.conf
    echo "Service = '-http'" | sudo tee -a /etc/logwatch/conf/logwatch.conf
    echo "Service = '-eximstats'" | sudo tee -a /etc/logwatch/conf/logwatch.conf

    logwatch --detail Low --range today

    # Sets up SSH
    sshd -t -f /etc/ssh/sshd_config
    echo "Banner /etc/issue.net" | sudo tee -a /etc/ssh/sshd_config
    systemctl restart sshd.service

    # Editing sshd_config to set too many things to count.
    echo "PermitRootLogin no"         | sudo tee -a /etc/ssh/sshd_config
    echo "PermitUserEnvironment no"   | sudo tee -a /etc/ssh/sshd_config
    echo "PermitEmptyPasswords no"    | sudo tee -a /etc/ssh/sshd_config
    echo "Protocol 2"                 | sudo tee -a /etc/ssh/sshd_config
    echo "PrintLastLog no"            | sudo tee -a /etc/ssh/sshd_config
    echo "PubkeyAuthentication yes"   | sudo tee -a /etc/ssh/sshd_config
    echo "RSAAuthentication yes"      | sudo tee -a /etc/ssh/sshd_config
    echo "LoginGraceTime 30"          | sudo tee -a /etc/ssh/sshd_config
    echo "ClientAliveInterval 600"    | sudo tee -a /etc/ssh/sshd_config
    echo "ClientAliveCountMax 1"      | sudo tee -a /etc/ssh/sshd_config
    echo "UsePAM yes"                 | sudo tee -a /etc/ssh/sshd_config
    echo "UsePrivilegeSeparation yes" | sudo tee -a /etc/ssh/sshd_config
    echo "StrictModes yes"            | sudo tee -a /etc/ssh/sshd_config
    echo "IgnoreUserKnownHosts yes"   | sudo tee -a /etc/ssh/sshd_config
    echo "IgnoreRhosts yes"           | sudo tee -a /etc/ssh/sshd_config
    echo "RhostsAuthentication no"    | sudo tee -a /etc/ssh/sshd_config
    echo "RhostsRSAAuthentication no" | sudo tee -a /etc/ssh/sshd_config
    echo "HostBasedAuthentication no" | sudo tee -a /etc/ssh/sshd_config
    echo "AllowTcpForwarding no"      | sudo tee -a /etc/ssh/sshd_config
    echo "X11Forwarding no"           | sudo tee -a /etc/ssh/sshd_config
    echo "LogLevel VERBOSE"           | sudo tee -a /etc/ssh/sshd_config
    echo "Port 2453"                  | sudo tee -a /etc/ssh/sshd_config

    # Editing rkhunter permissions
    echo "UPDATE_MIRRORS=1" | sudo tee -a "/etc/rkhunter.conf"
    echo "CRON_DAILY_RUN=true" | sudo tee -a "/etc/rkhunter.conf"
    echo "ALLOW_SSH_ROOT_USER=no" | sudo tee -a "/etc/rkhunter.conf"
    echo "ALOW_SSH_PROT_1=no" | sudo tee -a "/etc/rkhunter.conf"
    echo "ALLOW_SYSLOG_REMOTE=no" | sudo tee -a "/etc/rkhunter.conf"
    echo "USER_SYSLOG=authpriv.notice" | sudo tee -a "/etc/rkhunter.conf"

    # Forcing sudo authentication
    echo "Defaults authenticate" | sudo tee -a "/etc/sudoers"

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
    ufw deny icmp
    ufw default deny
    ufw --force enable

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
    echo "PASS_MAX_DAYS 90" | sudo tee -a "/etc/login.defs"
    echo "PASS_MIN_DAYS 7"  | sudo tee -a "/etc/login.defs"
    echo "PASS_WARN_AGE 14" | sudo tee -a "/etc/login.defs"
    echo "LOGIN_RETRIES 3"  | sudo tee -a "/etc/login.defs"
    echo "LOGIN_TIMEOUT 30" | sudo tee -a "/etc/login.defs"

    # Setting lockout policy (deny after 10 attempts, lock for 30 minutes)
    echo "auth required pam_tally2.so deny=10 unlock_time=1800" | sudo tee -a "/etc/pam.d/common-auth"

    # Setting minimum password length and how many passwords to remember
    echo "password required pam_unix.so minlen=8 remember=5" | sudo tee -a "/etc/pam.d/common-password"

    # Managing password complexity requirements (minimum length of 8, 1 upper, 1 lower, 1 digit, 1 special)
    echo "password required pam_cracklib.so minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" | sudo tee -a "/etc/pam.d/common-password"

    # Disallowing guest
    echo "allow-guest=false" | sudo tee -a "/etc/lightdm/lightdm.conf"

    # Forces user authentication for sudo.  I can't use editFile for this because I can't append it and Defaults appears many times.
    sed -i "9 a\Defaults env_reset, timestamp_timeout=0" /etc/sudoers
    sed -i "9 d" /etc/sudoers

    # Managing FTP permissions (Removing write commands and allowing ssl)
    echo "cmds_denied rmdir send rename put mput mdelete delete chmod" | sudo tee -a "/etc/vsftpd.conf"
    echo "ssl_enable=YES" | sudo tee -a "/etc/vsftpd.conf"
    echo "listen_ipv6=NO" | sudo tee -a "/etc/vsftpd.conf"
    echo "anonymous_enable=NO" | sudo tee -a "/etc/vsftpd.conf"
    echo "guest_enable=NO" | sudo tee -a "/etc/vsftpd.conf"
    echo "userlist_deny=YES" | sudo tee -a "/etc/vsftpd.conf"
    echo "root" | sudo tee "/etc/vsftpd/user_list"

    # Disabling SMTP
    sudo service sendmail stop

    # Puts the cron jobs onto the desktop.  (Both user and root)
    for filename in /var/spool/cron/crontabs/*; do
        cat "$filename" | sudo tee -a cronjobs.txt
    done
    cat /etc/crontab | sudo tee -a cronjobs.txt
    # Use 'crontab -r' to remove unnecessary jobs.

    # Enabling ASLR
    sysctl -w kernel.randomize_va_space 2
    # Enabling cookie protection
    sysctl -w net.ipv4.tcp_syncookies 1
    # Disabling ipv6
    sysctl -w net.ipv6.conf.all.disable_ipv6 1
    # Disabling IP forwarding
    sysctl -w net.ipv4.ip_forward 0
    # Hiding kernel pointer from unprivileged users
    sysctl -w kernel.kptr_restrict 1

    # Preventing IP Spoofing
    echo "nospoof on" | sudo tee -a /etc/host.conf

    # Saving active services
    systemctl list-units --type=service --state=active > services.txt

    # Saving prohibited file paths
    find / -type f -name "*.mp3"   >> audio.txt
    find / -type f -name "*.ac3"   >> audio.txt
    find / -type f -name "*.aac"   >> audio.txt
    find / -type f -name "*.aiff"  >> audio.txt
    find / -type f -name "*.flac"  >> audio.txt
    find / -type f -name "*.m4a"   >> audio.txt
    find / -type f -name "*.m4p"   >> audio.txt
    find / -type f -name "*.midi"  >> audio.txt
    find / -type f -name "*.mp2"   >> audio.txt
    find / -type f -name "*.m3u"   >> audio.txt
    find / -type f -name "*.ogg"   >> audio.txt
    find / -type f -name "*.vqf"   >> audio.txt
    find / -type f -name "*.wav"   >> audio.txt
    find / -type f -name "*.wma"   >> vids.txt
    find / -type f -name "*.mp4"   >> vids.txt
    find / -type f -name "*.avi"   >> vids.txt
    find / -type f -name "*.mpeg4" >> vids.txt
    find / -type f -name "*.gif"   >> pics.txt
    find / -type f -name "*.png"   >> pics.txt
    find / -type f -name "*.bmp"   >> pics.txt
    find / -type f -name "*.jpg"   >> pics.txt
    find / -type f -name "*.jpeg"  >> pics.txt

    # Changes the passwords for all users
    echo "Setting all passwords to Somethingsecur3!"
    for user in $(getent passwd | awk -F: '{if ($3 > 999) print $1}')
    do
        echo "$user:Somethingsecur3!" | chpasswd
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

    # These commands will remove admin rights from all users and then give them back
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

    echo "Check the files in this directory to find more vulnerabilities."
    echo "Manage Software Updater (Things like installing important security updates and automatically checking for updates daily)"

    read -rp "Press [Enter] to return to the menu."
    clear
    main
}

function managePorts {
    # Checks for open ports.
    touch pids.txt
    touch ports.txt
    netstat -tulpna | awk '{if ($7 != "-" && $7 != "" && $7 != "Address") print $7;}' | sudo tee -a pids.txt   # Puts the process ids into a text file
    netstat -tulpna | awk '{if ($7 != "-" && $7 != "" && $4 != "Local") print $4;}'   | sudo tee -a ports.txt  # Puts the ports into a text file

    touch finalPorts.txt
    while read -r -u 10 pid && read -r -u 11 port
    do
        printf "Port: %s, PID: %s" "$port" "$pid" | sudo tee -a finalPorts.txt  # Puts an outline of each port and the pid/command using it.
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