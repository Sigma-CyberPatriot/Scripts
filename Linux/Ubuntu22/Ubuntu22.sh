#!/bin/bash

# To get this script to work, run "chmod +x ./main.sh"
# To find all apt apps installed, run "apt list --installed"
# Please run this script as root.

# Adding execute permissions to the other files.  This will allow them to be used by this program.
chmod +x ./AppSetup/auditd.sh
chmod +x ./AppSetup/chkrootkit.sh
chmod +x ./AppSetup/clamav.sh
chmod +x ./AppSetup/logwatch.sh
chmod +x ./AppSetup/openssh-server.sh
chmod +x ./AppSetup/openssl.sh
chmod +x ./AppSetup/rkhunter.sh
chmod +x ./AppSetup/rsyslod.sh
chmod +x ./AppSetup/ufw.sh

# Variables
pass="SigmaHolo23!"

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
function start {
   # Differences  -- Implement later
   # Editing host.conf
   #cp /etc/host.conf /etc/host.conf.bak #>/dev/null 2>&1
   #echo "nospoof on" | tee -a /etc/host.conf #>/dev/null 2>&1
   #echo "order bind,hosts" | tee -a /etc/host.conf #>/dev/null 2>&1
   #ip link set dev promisc off #>/dev/null 2>&1

   # Installing apt-get
   wget http://us.archive.ubuntu.com/ubuntu/pool/main/a/apt/libapt-pkg6.0_2.4.11_amd64.deb -O libapt.deb >/dev/null 2>&1
   wget http://us.archive.ubuntu.com/ubuntu/pool/main/a/apt/apt_2.4.11_amd64.deb -O apt.deb >/dev/null 2>&1
   wget http://us.archive.ubuntu.com/ubuntu/pool/main/a/apt/apt-utils_2.4.11_amd64.deb -O apt-utils.deb >/dev/null 2>&1
   dpkg -i libapt.deb >/dev/null 2>&1 
   dpkg -i apt.deb >/dev/null 2>&1
   dpkg -i apt-utils.deb >/dev/null 2>&1
   
   # Editing sources.list
   echo "deb http://us.archive.ubuntu.com/ubuntu focal main multiverse restricted universe" | tee /etc/apt/sources.list
   echo "deb http://us.archive.ubuntu.com/ubuntu focal-security main multiverse restricted universe" | tee -a /etc/apt/sources.list
   echo "deb http://us.archive.ubuntu.com/ubuntu focal-updates main multiverse restricted universe" | tee -a /etc/apt/sources.list
   echo "deb http://archive.canonical.com/ubuntu focal partner" | tee -a /etc/apt/sources.list

   # Updating all apps (snaps included)
   apt-get update >/dev/null 2>&1
   apt-get upgrade -y >/dev/null 2>&1
   snap refresh >/dev/null 2>&1

   # Installing apps
   apt-get install -y auditd >/dev/null 2>&1
   apt-get install -y chkrootkit >/dev/null 2>&1
   apt-get install -y clamav >/dev/null 2>&1
   apt-get install -y cron >/dev/null 2>&1
   apt-get install -y git >/dev/null 2>&1
   apt-get install -y libdate-manip-perl >/dev/null 2>&1
   apt-get install -y libpam-cracklib >/dev/null 2>&1
   apt-get install -y logwatch >/dev/null 2>&1
   apt-get install -y nano >/dev/null 2>&1
   apt-get install -y net-tools >/dev/null 2>&1
   apt-get install -y openssl >/dev/null 2>&1
   apt-get install -y openssh >/dev/null 2>&1
   apt-get install -y rkhunter >/dev/null 2>&1
   apt-get install -y rsyslod >/dev/null 2>&1
   apt-get install -y ufw >/dev/null 2>&1

   # Updating again to make sure everything is up to date (Can't be too careful!)
   apt-get update >/dev/null 2>&1
   apt-get upgrade -y >/dev/null 2>&1
   apt-get --fix-broken install -y >/dev/null 2>&1
   snap refresh >/dev/null 2>&1

   # Uninstalling prohibited apps
   # Hacking tools
   apt-get remove -y aircrack-ng >/dev/null 2>&1
   apt-get remove -y apache2 >/dev/null 2>&1
   apt-get remove -y apktool >/dev/null 2>&1
   apt-get remove -y autopsy >/dev/null 2>&1
   apt-get remove -y deluge >/dev/null 2>&1
   apt-get remove -y dirb >/dev/null 2>&1
   apt-get remove -y dsniff >/dev/null 2>&1
   apt-get remove -y ettercap >/dev/null 2>&1
   apt-get remove -y fcracklib >/dev/null 2>&1
   apt-get remove -y ftp >/dev/null 2>&1
   apt-get remove -y httrack >/dev/null 2>&1
   apt-get remove -y hydra >/dev/null 2>&1
   apt-get remove -y john-the-ripper >/dev/null 2>&1
   apt-get remove -y kismet >/dev/null 2>&1
   apt-get remove -y linuxdcpp >/dev/null 2>&1
   apt-get remove -y metasploit-framework >/dev/null 2>&1
   apt-get remove -y netcat >/dev/null 2>&1
   apt-get remove -y nikto >/dev/null 2>&1
   apt-get remove -y nmap >/dev/null 2>&1
   apt-get remove -y rfdump >/dev/null 2>&1
   apt-get remove -y skipfish >/dev/null 2>&1
   apt-get remove -y snort >/dev/null 2>&1
   apt-get remove -y sqlmap >/dev/null 2>&1
   apt-get remove -y wifite >/dev/null 2>&1
   apt-get remove -y wireshark >/dev/null 2>&1
   apt-get remove -y yersinia >/dev/null 2>&1
   apt-get remove -y zenmap >/dev/null 2>&1
   # Games
   apt-get remove -y aisleriot >/dev/null 2>&1
   apt-get remove -y endless-sky >/dev/null 2>&1
   apt-get remove -y freeciv >/dev/null 2>&1
   apt-get remove -y gnome-mahjongg >/dev/null 2>&1
   apt-get remove -y gnome-mines >/dev/null 2>&1
   apt-get remove -y gnome-sudoku >/dev/null 2>&1
   apt-get remove -y gnomine >/dev/null 2>&1
   apt-get remove -y wesnoth >/dev/null 2>&1
   # Insecure software
   apt-get remove -y ldap-utils >/dev/null 2>&1
   apt-get remove -y manaplus >/dev/null 2>&1
   apt-get remove -y nis >/dev/null 2>&1
   apt-get remove -y rpcbind >/dev/null 2>&1
   apt-get remove -y rsh-client >/dev/null 2>&1
   apt-get remove -y rsh-server >/dev/null 2>&1
   apt-get remove -y rsync >/dev/null 2>&1
   apt-get remove -y talk >/dev/null 2>&1
   apt-get remove -y telnet >/dev/null 2>&1
   apt-get remove -y telnetd >/dev/null 2>&1
   # Unnecessary bloatware
   apt-get remove -y apport >/dev/null 2>&1
   apt-get remove -y atd >/dev/null 2>&1
   apt-get remove -y autofs >/dev/null 2>&1
   apt-get remove -y avahi-daemon >/dev/null 2>&1
   apt-get remove -y avahi-utils >/dev/null 2>&1
   apt-get remove -y bind9 >/dev/null 2>&1
   apt-get remove -y cups >/dev/null 2>&1
   apt-get remove -y dovecot-imapd >/dev/null 2>&1
   apt-get remove -y dovecot-pop3d >/dev/null 2>&1
   apt-get remove -y iptables-persistent >/dev/null 2>&1
   apt-get remove -y isc-dhcp-server >/dev/null 2>&1
   apt-get remove -y nfs-common >/dev/null 2>&1
   apt-get remove -y nfs-kernel-server >/dev/null 2>&1
   apt-get remove -y nginx >/dev/null 2>&1
   apt-get remove -y portmap >/dev/null 2>&1
   apt-get remove -y python-zeitgeist >/dev/null 2>&1
   apt-get remove -y rhythmbox-plugin-zeitgeist >/dev/null 2>&1
   apt-get remove -y rpcbind >/dev/null 2>&1
   apt-get remove -y slapd >/dev/null 2>&1
   apt-get remove -y squid >/dev/null 2>&1
   apt-get remove -y xserver-xorg* >/dev/null 2>&1
   apt-get remove -y zeitgeist >/dev/null 2>&1
   apt-get remove -y zeitgeist-core >/dev/null 2>&1
   apt-get remove -y zeitgeist-datahub >/dev/null 2>&1

   # Updating again to make sure everything is up to date (Can't be too careful!)
   apt-get update >/dev/null 2>&1
   apt-get upgrade -y >/dev/null 2>&1
   apt-get --fix-broken install -y >/dev/null 2>&1
   snap refresh >/dev/null 2>&1

   # Enabling automatic updates.
   dpkg-reconfigure --priority=low unattended-upgrades >/dev/null 2>&1
   unattended-upgrade -d >/dev/null 2>&1

   # Changing all user passwords.
   for user in $(getent passwd | awk -F: '{if ($3 > 999 && $3 != 65534) print $1}')
   do
      chpasswd "$user:$pass"
   done

   

   ## Fixing System file permissions
   # chmod 000 /etc/shadow #>/dev/null 2>&1
   # chmod 644 /etc/passwd #>/dev/null 2>&1
   # chmod 640 /var/log #>/dev/null 2>&1
   # chmod 640 /var/log/syslog #>/dev/null 2>&1
   # chown syslog /var/log/syslog #>/dev/null 2>&1
   # chown root /var/log #>/dev/null 2>&1
   # chgrp adm /var/log/syslog #>/dev/null 2>&1
   # chmod 755 /bin #>/dev/null 2>&1
   # chmod 755 /sbin #>/dev/null 2>&1
   # chmod 755 /usr/bin #>/dev/null 2>&1
   # chmod 755 /usr/sbin #>/dev/null 2>&1
   # chmod 755 /usr/local/bin #>/dev/null 2>&1
   # chmod 755 /usr/local/sbin #>/dev/null 2>&1

   # Editing system files
   # Editing /etc/login.defs to set a max passwd age(90), min passwd age(7), warn age(14), number of retries(3), and a login timeout(30).
   echo "PASS_MAX_DAYS 90" | tee -a /etc/login.defs #>/dev/null 2>&1
   echo "PASS_MIN_DAYS 7"  | tee -a /etc/login.defs #>/dev/null 2>&1
   echo "PASS_WARN_AGE 14" | tee -a /etc/login.defs #>/dev/null 2>&1
   echo "LOGIN_RETRIES 3"  | tee -a /etc/login.defs #>/dev/null 2>&1
   echo "LOGIN_TIMEOUT 30" | tee -a /etc/login.defs #>/dev/null 2>&1
   # Editing /etc/pam.d/common-auth to add 'deny=5 unlock_time=1800' to end of 'pam_tally2.so'
   echo "pam_tally2.so deny=10 unlock_time=1800" | tee -a /etc/pam.d/common-auth #>/dev/null 2>&1
   # Editing /etc/pam.d/common-password to add 'minlen=8 remember=5' to 'pam_unix.so', and add 'ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-' to 'pam_cracklib.so'.
   echo "pam_unix.so minlen=8 remember=5" | tee -a /etc/pam.d/common-password #>/dev/null 2>&1
   echo "pam_cracklib.so ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-" | tee -a /etc/pam.d/common-password #>/dev/null 2>&1
   # Editing /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf to add 'allow-guest=false'. May cause an error.
   echo "allow-guest=false" | tee -a /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf #>/dev/null 2>&1

   # Disabling unnecessary services
   # DNS Server
   echo DNSStubListener=no | tee -a /etc/systemd/resolved.conf; #>/dev/null 2>&1
   systemctl stop systemd-resolved; #>/dev/null 2>&1
   systemctl disable systemd-resolved #>/dev/null 2>&1
   # inetd
   echo inetd_enable=no | tee -a /etc/rc.conf #>/dev/null 2>&1
   # NFS Server
   systemctl stop nfs #>/dev/null 2>&1

   # Puts the cron jobs onto the desktop.  (Both user and root)
   for filename in /var/spool/cron/crontabs/*; do
      cat "$filename" | tee -a /var/output/cronjobs.txt
   done
   cat /etc/crontab | tee -a /var/output/cronjobs.txt
   # Use 'crontab -r' to remove unnecessary jobs.

   # Network Protections (Lines 74-90)
   # Setting up firewall
   ufw allow in on lo #>/dev/null 2>&1
   ufw allow out on lo #>/dev/null 2>&1
   ufw deny in from 127.0.0.0/8 #>/dev/null 2>&1
   ufw deny in from ::1 #>/dev/null 2>&1
   ufw allow ssh #>/dev/null 2>&1
   ufw allow http #>/dev/null 2>&1
   ufw deny 23 #>/dev/null 2>&1
   ufw default deny #>/dev/null 2>&1
   ufw --force enable #>/dev/null 2>&1

   # Enabling cookie protection
   sysctl -n net.ipv4.tcp_syncookies #>/dev/null 2>&1
   # Disabling ipv6
   echo "net.ipv6.conf.all.disable_ipv6 = 1" | tee -a /etc/sysctl.conf #>/dev/null 2>&1
   # Disabling IP forwarding
   echo 0 | tee -a /proc/sys/net/ipv4/ip_forward #>/dev/null 2>&1
   # Preventing IP Spoofing
   echo "nospoof on" | tee -a /etc/host.conf #>/dev/null 2>&1

   # Deleting prohibited files (This may delete files needed for the image, be careful!)
   find / -type f -name "*.mp3"   -delete #>/dev/null 2>&1
   find / -type f -name "*.ac3"   -delete #>/dev/null 2>&1
   find / -type f -name "*.aac"   -delete #>/dev/null 2>&1
   find / -type f -name "*.aiff"  -delete #>/dev/null 2>&1
   find / -type f -name "*.flac"  -delete #>/dev/null 2>&1
   find / -type f -name "*.m4a"   -delete #>/dev/null 2>&1
   find / -type f -name "*.m4p"   -delete #>/dev/null 2>&1
   find / -type f -name "*.midi"  -delete #>/dev/null 2>&1
   find / -type f -name "*.mp2"   -delete #>/dev/null 2>&1
   find / -type f -name "*.m3u"   -delete #>/dev/null 2>&1
   find / -type f -name "*.ogg"   -delete #>/dev/null 2>&1
   find / -type f -name "*.vqf"   -delete #>/dev/null 2>&1
   find / -type f -name "*.wav"   -delete #>/dev/null 2>&1
   find / -type f -name "*.wma"   -delete #>/dev/null 2>&1
   find / -type f -name "*.mp4"   -delete #>/dev/null 2>&1
   find / -type f -name "*.avi"   -delete #>/dev/null 2>&1
   find / -type f -name "*.mpeg4" -delete #>/dev/null 2>&1
   find / -type f -name "*.gif"   -delete #>/dev/null 2>&1
   find / -type f -name "*.png"   -delete #>/dev/null 2>&1
   find / -type f -name "*.bmp"   -delete #>/dev/null 2>&1
   find / -type f -name "*.jpg"   -delete #>/dev/null 2>&1
   find / -type f -name "*.jpeg"  -delete #>/dev/null 2>&1

   # This creates users 
   while true
   do
      echo "Enter the name of a user to add.  Type '0' to move on."
      read -r user
      if [ "$user" -eq 0 ]
         then break
      else
         useradd "$user" -m #>/dev/null 2>&1
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
         groupadd "$group" -m #>/dev/null 2>&1
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
         usermod -aG "$group" "$user" #>/dev/null 2>&1
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
         userdel "$user" #>/dev/null 2>&1
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
         groupdel "$group" #>/dev/null 2>&1
      fi
   done

   # These commands will remove admin rights from all users and then give them back to the users specified in the admins array.
   # Removing admin permissions
   for user in $(getent passwd | awk -F: '{if ($3 > 999 && $3 != 65534) print $1}')
   do
      usermod -G "$user" "$user" #>/dev/null 2>&1
   done
   
   # Giving back admin permissions
   while true
   do
      echo "Enter the name of a admin to add.  Type '0' to move on."
      read -r admin
      if [ "$admin" -eq 0 ]
         then break
      else
         usermod -aG "sudo" "$admin" #>/dev/null 2>&1
      fi
   done

   read -rp "Press [Enter] to return to the menu."
   clear
   main
}

function managePorts {
   # Checks for open ports.
   touch pids.txt
   touch ports.txt
   netstat -tulpna | awk '{if ($7 != "-" && $7 != "" && $7 != "Address") print $7;}' | tee -a pids.txt  #>/dev/null 2>&1 # Puts the process ids into a text file
   netstat -tulpna | awk '{if ($7 != "-" && $7 != "" && $4 != "Local") print $4;}'   | tee -a ports.txt #>/dev/null 2>&1 # Puts the ports into a text file

   touch finalPorts.txt
   while read -r -u 10 pid && read -r -u 11 port
   do
      printf "Port: %s, PID: %s" "$port" "$pid" | tee -a finalPorts.txt #>/dev/null 2>&1 # Puts an outline of each port and the pid/command using it.
   done 10<pids.txt 11<ports.txt

   # Removing unnecessary files.
   rm pids.txt #>/dev/null 2>&1
   rm ports.txt #>/dev/null 2>&1
   
   # Windows command is netstat -ano, in case that is ever helpful.
   while (true)
   do
      VAR10=0
      VAR11=""
      echo "What port do you want to close?"
      read -r VAR10
      ufw deny "$VAR10" #>/dev/null 2>&1
      echo "Do you want to close another port? [Y/n]"
      read -r VAR11
      if [ "$VAR11" != "Y" ] && [ "$VAR11" != "y" ]; then
         break #>/dev/null 2>&1
      fi
   done
}

# This function contains deprecated code that may be useful some other time.  It is never run in the program
function deprecated {
   # Firefox is no longer used by CyberPatriot, but just in case...
   # Manages Firefox settings
   wget https://github.com/pyllyukko/user.js/raw/master/user.js #>/dev/null 2>&1
   mv ./user.js /etc/firefox/user.js #>/dev/null 2>&1

   FirefoxPref() {
      echo "user_pref($1, $2);" | tee -a user.js #>/dev/null 2>&1
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