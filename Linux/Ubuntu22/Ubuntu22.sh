#!/bin/bash

# To get this script to work, run "chmod +x ./main.sh"
# To find all apt apps installed, run "apt list --installed"
# Please run this script as root.

# Adding execute permissions to the other files.  This will allow them to be used by this program.
chmod +x /var/scripts/auditd.sh
chmod +x /var/scripts/chkrootkit.sh
chmod +x /var/scripts/clamav.sh
chmod +x /var/scripts/libdate-manip-perl.sh
chmod +x /var/scripts/libpam-cracklib.sh
chmod +x /var/scripts/logwatch.sh
chmod +x /var/scripts/managePorts.sh
chmod +x /var/scripts/nano.sh
chmod +x /var/scripts/net-tools.sh
chmod +x /var/scripts/openssl.sh
chmod +x /var/scripts/rkhunter.sh
chmod +x /var/scripts/rsyslod.sh
chmod +x /var/scripts/ufw.sh

# Variables
pass="Jax1@joe"
admins=("turbo")
userstoadd=("user3" "user4")
groupstoadd=("group3" "group4")
userstodel=("user1" "user2")
groupstodel=("group1" "group2")

echo Note that any new groups will be empty, as I cannot make lists of lists.

# This is the main function.  It acts as a menu.
function main {
   printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
   printf "   ______    ______    ______    __       __    ______               __      __    ________     __             ________   \n"
   printf "  /      \  /      |  /      \  /  \     /  |  /      \             /  |    /  |  /        \   /  |           /        \  \n"
   printf " /&&&&&&  | &&&&&&/  /&&&&&&  | &&  \   /&& | /&&&&&&  |            && |    && | /&&&&&&&&  |  && |          /&&&&&&&&  | \n"
   printf " && \__&&/    && |   && | _&&/  &&$  \ /&&$ | && |__&& |   ______   && |    && | && |    && |  && |          && |    && | \n"
   printf " &&      \    && |   && |/    | &&&&  /&&&& | &&    && |  |______|  && |    && | && |    && |  && |          && |    && | \n"
   printf "  &&&&&&  |   && |   && |&&&& | && && &&/&& | &&&&&&&& |            &&&&&&&&&& | && |    && |  && |          && |    && | \n"
   printf " /  \__&& |  _&& |_  && \__&& | && |&&$/ && | && |  && |            && |    && | && |    && |  && |_______   && |    && | \n"
   printf " &&    &&/  / &&   | &&    &&/  && | $/  && | && |  && |            && |    && | && \    && |  &&         |  && \    && | \n"
   printf "  &&&&&&/   &&&&&&/   &&&&&&/   &&/      &&/  &&/   &&/             &&/     &&/   &&&&&&&&_/   &&&&&&&&&&/    &&&&&&&&_/  \n"
   printf "              __     __   _______    __     __   ___      __   ________   __     __        ______     ______              \n"
   printf "             /  |   /  | /       \  /  |   /  | /   \    /  | /        | /  |   /  |      /      \   /      \             \n"
   printf "             && |   && | &&&&&&&  \ && |   && | &&&& \   && | &&&&&&&&_/ && |   && |     /&&&&&&  | /&&&&&&  |            \n"
   printf "             && |   && | && |  && | && |   && | && && \  && |    && |    && |   && |     &&_/  && | &&_/  && |            \n"
   printf "             && |   && | && |  && / && |   && | && &&  \ && |    && |    && |   && |           && |       && |            \n"
   printf "             && |   && | &&&&&&& <  && |   && | && | && \&& |    && |    && |   && |          && /       && /             \n"
   printf "             && |   && | && |  && \ && |   && | && | &&  && |    && |    && |   && |        &&& /      &&& /              \n"
   printf "             && |   && | && |  && | && |   && | && |  && && |    && |    && |   && |      &&&  /___  &&&  /___            \n"
   printf "              &&&&&&&_/  &&&&&&&__/  &&&&&&&_/  &&/    &&&&/     &&_/     &&&&&&&_/      &&&&&&&&_/ &&&&&&&&_/            \n"
   printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Written by: Jackson Campbell ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
   printf "    1) Start                                                                                                              \n"
   printf "    2) View checklist                                                                                                     \n"
   printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"

   read -r answer
   if [ "$answer" -eq 1 ]; then start; fi
   if [ "$answer" -eq 2 ]; then checkList; fi
}

function start {
   # Differences  -- Implement later
   # Editing host.conf
   cp /etc/host.conf /etc/host.conf.bak
   echo "nospoof on" | tee -a /etc/host.conf
   echo "order bind,hosts" | tee -a /etc/host.conf
   ip link set dev promisc off 

   # Installing apt-get
   wget http://security.ubuntu.com/ubuntu/pool/main/a/apt/apt_2.7.2_i386.deb -O apt-get.deb
   dpkg -i apt-get.deb

   # Updating all apps (snaps included)
   apt-get update
   apt-get upgrade
   snap refresh

   # Installing apps
   apt-get install -y auditd
   apt-get install -y chkrootkit
   apt-get install -y clamav
   apt-get install -y cron
   apt-get install -y git
   apt-get install -y libdate-manip-perl
   apt-get install -y libpam-cracklib
   apt-get install -y logwatch
   apt-get install -y nano
   apt-get install -y net-tools
   apt-get install -y openssl
   apt-get install -y rkhunter
   apt-get install -y rsyslod
   apt-get install -y ufw

   # Updating again to make sure everything is up to date (Can't be too careful!)
   apt-get update
   apt-get upgrade
   snap refresh

   # Enabling automatic updates.
   dpkg-reconfigure --priority=low unattended-upgrades
   unattended-upgrade -d

   # Uninstalling prohibited apps
   # Hacking tools
   apt-get remove aircrack-ng
   apt-get remove apache2
   apt-get remove apktool
   apt-get remove autopsy
   apt-get remove deluge
   apt-get remove dirb
   apt-get remove dsniff
   apt-get remove ettercap
   apt-get remove fcracklib
   apt-get remove ftp
   apt-get remove httrack
   apt-get remove hydra
   apt-get remove john-the-ripper
   apt-get remove kismet
   apt-get remove linuxdcpp
   apt-get remove metasploit-framework
   apt-get remove netcat
   apt-get remove nikto
   apt-get remove nmap
   apt-get remove rfdump
   apt-get remove skipfish
   apt-get remove snapd
   apt-get remove snort
   apt-get remove sqlmap
   apt-get remove wifite
   apt-get remove wireshark
   apt-get remove yersinia
   apt-get remove zenmap
   # Games
   apt-get remove aisleriot
   apt-get remove endless-sky
   apt-get remove freeciv
   apt-get remove gnome-mahjongg
   apt-get remove gnome-mines
   apt-get remove gnome-sudoku
   apt-get remove gnomine
   apt-get remove wesnoth
   # Insecure software
   apt-get remove ldap-utils
   apt-get remove manaplus
   apt-get remove nis
   apt-get remove rpcbind
   apt-get remove rsh-client
   apt-get remove rsh-server
   apt-get remove rsync
   apt-get remove talk
   apt-get remove telnet
   apt-get remove telnetd
   # Unnecessary bloatware
   apt-get remove apport
   apt-get remove atd
   apt-get remove autofs
   apt-get remove avahi-daemon
   apt-get remove avahi-utils
   apt-get remove bind9
   apt-get remove cups
   apt-get remove dovecot-imapd
   apt-get remove dovecot-pop3d
   apt-get remove iptables-persistent
   apt-get remove isc-dhcp-server
   apt-get remove nfs-common
   apt-get remove nfs-kernel-server
   apt-get remove nginx
   apt-get remove portmap
   apt-get remove python-zeitgeist
   apt-get remove rhythmbox-plugin-zeitgeist
   apt-get remove rpcbind
   apt-get remove slapd
   apt-get remove squid
   apt-get remove xserver-xorg*
   apt-get remove zeitgeist
   apt-get remove zeitgeist-core
   apt-get remove zeitgeist-datahub

   # Removing unused dependencies
   apt-get autoremove

   # Runs the Clam antivirus.
   clamscan -r --remove /

   # Manages Firefox settings
   wget https://github.com/pyllyukko/user.js/raw/master/user.js
   mv ./user.js /etc/firefox/user.js

   FirefoxPref() {
      echo "pref($1, $2);" | tee -a user.js
   }

   FirefoxPref '"browser.safebrowsing.downloads.enabled"' "true"
   FirefoxPref '"browser.safebrowsing.downloads.remote.enabled"' "true"
   FirefoxPref '"browser.safebrowsing.downloads.remote.block_dangerous"' "true"
   FirefoxPref '"browser.safebrowsing.downloads.remote.block_dangerous"' "true"
   FirefoxPref '"browser.safebrowsing.downloads.remote.block_dangerous_host"' "true"
   FirefoxPref '"browser.safebrowsing.downloads.remote.block_potentially_unwanted"' "true"
   FirefoxPref '"browser.safebrowsing.downloads.remote.block_uncommon"' "true"
   FirefoxPref '"browser.safebrowsing.malware.enabled"' "true"
   FirefoxPref '"browser.safebrowsing.phishing.enabled"' "true"
   FirefoxPref '"dom.disable_during_load"' "true"
   FirefoxPref '"dom.block_multiple_popups"' "true"
   FirefoxPref '"dom.block_download_insecure"' "true"
   FirefoxPref '"dom.enable_performance"' "true"
   FirefoxPref '"dom.allow_scripts_to_close_windows"' "false"
   FirefoxPref '"media.autoplay.block-webaudio"' "true"
   FirefoxPref '"media.block-autoplay-until-in-foreground"' "true"
   FirefoxPref '"plugins.flashBlock.enabled"' "true"
   FirefoxPref '"privacy.socialtracking.block_cookies.enabled"' "true"
   FirefoxPref '"toolkit.telemetry.reportingpolicy.firstRun"' "false"

   # Fixing System file permissions
   chmod 000 /etc/shadow
   chmod 644 /etc/passwd
   chmod 600 /etc/ssh/ssh_host*key
   chmod 600 /etc/ssh/*key.pub
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

   # Edits system files
   # Editing /etc/login.defs to set a max passwd age(90), min passwd age(7), warn age(14), number of retries(3), and a login timeout(30).
   printf "PASS_MAX_DAYS  90\nPASS_MIN_DAYS  7\nPASS_WARN_AGE  14\nLOGIN_RETRIES 3\nLOGIN_TIMEOUT  30" | tee -a /etc/login.defs
   # Editing sshd_config to set too many things to count.
   printf "PermitRootLogin no\nPermitUserEnvironment no\nPermitEmptyPasswords no\nProtocol 2\nPrintLastLog no\nPubkeyAuthentication yes\nRSAAuthentication yes\nLoginGraceTime 30\nClientAliveInterval 600\nClientAliveCountMax 1\nUsePAM yes\nUsePrivilegeSeparation yes\nStrictModes yes\nIgnoreUserKnownHosts yes\nIgnoreRhosts yes\nRhostsAuthentication no\nRhostsRSAAuthentication no\nHostBasedAuthentication no\nAllowTcpForwarding no\nX11Forwarding no\nLogLevel VERBOSE\nPort 2453" | tee -a /etc/ssh/sshd_config
   # Editing /etc/pam.d/common-auth to add 'deny=5 unlock_time=1800' to end of 'pam_tally2.so'
   printf "pam_tally2.so   deny=10 unlock_time=1800" | tee -a /etc/pam.d/common-auth
   # Editing /etc/pam.d/common-password to add 'minlen=8 remember=5' to 'pam_unix.so', and add 'ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-' to 'pam_cracklib.so'.
   printf "pam_unix.so  minlen=8 remember=5\npam_cracklib.so   ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-" | tee -a /etc/pam.d/common-password
   # Editing /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf to add 'allow-guest=false'. May cause an error.
   printf "allow-guest=false" | tee -a /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf

   # Setting up audit services
   augenrules --load
   systemctl enable rsyslog
   systemctl restart rsyslog

   # Disabling unnecessary services
   echo DNSStubListener=no | tee -a /etc/systemd/resolved.conf; # DNS Server 1
   systemctl stop systemd-resolved; # DNS Server 2
   systemctl disable systemd-resolved # DNS Server 3
   echo inetd_enable=no | tee -a /etc/rc.conf # inetd
   systemctl stop nfs # NFS Server

   # Checks for open ports.
   netstat -tulpna | awk '{if ($7 != "-" && $7 != "" && $7 != "Address") print $7;}' | tee -a pids.txt  # Puts the process ids into a text file
   netstat -tulpna | awk '{if ($7 != "-" && $7 != "" && $4 != "Local") print $4;}'   | tee -a ports.txt # Puts the ports into a text file

   sed -i '1d' processes.txt
   while read -r -u 10 pid && read -r -u 11 port
   do
      command=$(ps -p "$pid" | awk '{if ($4 != "CMD") print $4;}')

      printf "Port: %s, Command: %s, PID: %s" "$port" "$command" "$pid" | tee -a /var/output/finalPorts.txt # Puts an outline of each port and the pid/command using it.
   done 10<pids.txt 11<ports.txt

   # Removing unnecessary files.
   rm pids.txt
   rm ports.txt

   # Windows command is netstat -ano, in case that is ever helpful.
   printf "When you have looked through the finalPorts.txt file in /var/output"
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

   # Puts the cron jobs onto the desktop.  (Both user and root)
   for filename in /var/spool/cron/crontabs/*; do
      cat "$filename" | tee -a /var/output/cronjobs.txt
   done
   cat /etc/crontab | tee -a /var/output/cronjobs.txt
   # Use 'crontab -r' to remove unnecessary jobs.

   # Network Protections (Lines 74-90)
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

   # Enabling cookie protection
   sysctl -n net.ipv4.tcp_syncookies

   # Disabling ipv6
   echo "net.ipv6.conf.all.disable_ipv6 = 1" | tee -a /etc/sysctl.conf

   # Disabling IP forwarding
   echo 0 | tee -a /proc/sys/net/ipv4/ip_forward

   # Preventing IP Spoofing
   echo "nospoof on" | tee -a /etc/host.conf

   # Deleting prohibited files (This may delete files needed for the image, be careful!)
   find / -type f -name "*.mp3" -delete

   # User Management (Lines 93-118)
   # This will create all the users specified in the userstoadd array.
   for user in "${userstoadd[@]}"
   do
      useradd "$user" -m
   done

   # This will create all the groups specified in the groupstoadd array as well as get the people that need to be added to that group.
   for group in "${groupstoadd[@]}"
   do
      groupadd "$group"
      printf "How many users should be in the group %s?" "$group"
      read -r count
      for ((i = 0; i < "$count"; i++))
      do
         echo "Please enter the name of user #$i"
         read -r user
         usermod -aG "$user"
      done
   done

   # Deletes all the users specified in the userstodel array.
   for user in "${userstodel[@]}"; do
      userdel "$user" -rf
   done

   # Deletes all the groups specified in the groupstodel array.
   for group in "${groupstodel[@]}"; do
      groupdel "$group" -f
   done

   # These commands will remove admin rights from all users and then give them back to the users specified in the admins array.
   # Removing admin permissions
   getent passwd | awk -F: '{if ($3 | tee -a 999 && $3 != 65534) print $1}' | xargs -I {} bash -c 'gpasswd -d "$@"' _ {}

   # Giving back admin permissions
   for admin in "${admins[@]}"; do
      gpasswd -a "$admin"
   done

   # This changes the password of every user to the 'pass' variable.  (Default = "h3lloworld")  Edit password above in the "Variables" section
   getent passwd | awk -F: '{if ($3 > 999) print $1;}' | xargs -Iuser -n 1 echo "user:$pass" | sudo chpasswd -e
   echo "$pass" | passwd root

   main
}

function checkList {
   printf "Checklist\n"
   printf "    1) Install and run ClamAV\n"
   printf "    2) Install and start ufw\n"
   printf "    3) Update apps\n"
   printf "    4) Read readme, there will definitely be something in there for points\n"
   printf "    5) Check past checklists (Here's one!).\n"
   printf "    6) Help teamates.\n"
   printf "    7) Get teamates to help you.\n"
   printf "    8) Win!!!\n\n"

   read -rp "Press any key to resume..."
   main
}

main