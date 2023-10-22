#!/bin/bash

# To get this script to work, run "chmod +x ./main.sh"
# To find all apt apps installed, run "apt list --installed"
# Please run this script as root.

# Adding execute permissions to the setup file.
chmod +x ./AppSetup.sh
source ./AppSetup.sh

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
   
   # Editing sources.list
   echo "deb http://us.archive.ubuntu.com/ubuntu focal main multiverse restricted universe" | tee /etc/apt/sources.list 
   echo "deb http://us.archive.ubuntu.com/ubuntu focal-security main multiverse restricted universe" | tee -a /etc/apt/sources.list 
   echo "deb http://us.archive.ubuntu.com/ubuntu focal-updates main multiverse restricted universe" | tee -a /etc/apt/sources.list 
   echo "deb http://archive.canonical.com/ubuntu focal partner" | tee -a /etc/apt/sources.list 

   # Making installs require secure ssl connection
   apt-get install -y wget ca-certificates 
   wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add - 
   echo "deb http://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main" | tee -a /etc/apt/sources.list.d/pgdg.list 

   # Updating all apps (snaps included)
   apt-get update 
   apt-get upgrade -y 
   snap refresh 

   # Installing apps
   apt-get install -y auditd; auditdSetup
   apt-get install -y chkrootkit; chkrootkitSetup
   apt-get install -y clamav; clamavSetup
   apt-get install -y cron
   apt-get install -y git
   apt-get install -y libdate-manip-perl
   apt-get install -y libpam-cracklib
   apt-get install -y logwatch; logwatchSetup
   apt-get install -y nano
   apt-get install -y net-tools
   apt-get install -y openssl; sslSetup
   apt-get install -y openssh-server; sshSetup
   apt-get install -y p7zip
   apt-get install -y postgresql postgresql-contrib
   apt-get install -y rkhunter; rkhunterSetup
   apt-get install -y rsyslod; rsyslodSetup
   apt-get install -y ufw; ufwSetup
   apt-get install -y unattended-upgrades; upgradeSetup

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
   snap refresh 

   # Enabling automatic updates and updating daily
   dpkg-reconfigure -plow unattended-upgrades 
   
   # Changing all user passwords.
   for user in $(getent passwd | awk -F: '{if ($3 > 999 && $3 != 65534) print $1}')
   do
      chpasswd "$user:$pass"
   done

   ## Fixing System file permissions
   chmod 000 /etc/shadow 
   chmod 644 /etc/passwd 
   chmod 640 /var/log 
   chmod 640 /var/log/syslog 
   chown syslog /var/log/syslog 
   chown root /var/log 
   chgrp adm /var/log/syslog 
   chmod 755 /bin 
   chmod 755 /sbin 
   #chmod 755 /usr/bin 
   #chmod 755 /usr/sbin 
   #chmod 755 /usr/local/bin 
   #chmod 755 /usr/local/sbin 

   # Editing /etc/login.defs to set a max passwd age(90), min passwd age(7), warn age(14), number of retries(3), and a login timeout(30).
   echo "PASS_MAX_DAYS 90" | tee -a /etc/login.defs 
   echo "PASS_MIN_DAYS 7"  | tee -a /etc/login.defs 
   echo "PASS_WARN_AGE 14" | tee -a /etc/login.defs 
   echo "LOGIN_RETRIES 3"  | tee -a /etc/login.defs 
   echo "LOGIN_TIMEOUT 30" | tee -a /etc/login.defs 

   # Setting lockout policy
   echo "pam_tally2.so deny=10 unlock_time=1800" | tee -a /etc/pam.d/common-auth 

   # Setting minimum password length and how many passwords to remember
   echo "pam_unix.so minlen=8 remember=5" | tee -a /etc/pam.d/common-password 

   # I don't know what this does, but it helps
   echo "pam_cracklib.so ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-" | tee -a /etc/pam.d/common-password 

   # Editing /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf to add 'allow-guest=false'. May cause an error.
   echo "allow-guest=false" | tee -a /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf 

   # Disabling ssh root login
   echo "PermitRootLogin=No" | tee -a /etc/ssh/sshd_config 

   # Forces user authentication for sudo
   # Gets the original 9th line
   old="$(sed '9q;d' /etc/sudoers)"
   # This is what it will be replaced with
   new="Defaults env_reset, timestamp_timeout=0"
   # Replaces the line with sed
   sed -i.bak "17 s/$old/$new/" /etc/sudoers
   
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
   find / -type f -name "*.mp3"   -delete 
   find / -type f -name "*.ac3"   -delete 
   find / -type f -name "*.aac"   -delete 
   find / -type f -name "*.aiff"  -delete 
   find / -type f -name "*.flac"  -delete 
   find / -type f -name "*.m4a"   -delete 
   find / -type f -name "*.m4p"   -delete 
   find / -type f -name "*.midi"  -delete 
   find / -type f -name "*.mp2"   -delete 
   find / -type f -name "*.m3u"   -delete 
   find / -type f -name "*.ogg"   -delete 
   find / -type f -name "*.vqf"   -delete 
   find / -type f -name "*.wav"   -delete 
   find / -type f -name "*.wma"   -delete 
   find / -type f -name "*.mp4"   -delete 
   find / -type f -name "*.avi"   -delete 
   find / -type f -name "*.mpeg4" -delete 
   find / -type f -name "*.gif"   -delete 
   find / -type f -name "*.png"   -delete 
   find / -type f -name "*.bmp"   -delete 
   find / -type f -name "*.jpg"   -delete 
   find / -type f -name "*.jpeg"  -delete 

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
}

# This function contains deprecated code that may be useful some other time.  It is never run in the program
function deprecated {
   # Firefox is no longer used by CyberPatriot, but just in case...
   # Manages Firefox settings
   wget https://github.com/pyllyukko/user.js/raw/master/user.js 
   mv ./user.js /etc/firefox/user.js 

   FirefoxPref() {
      echo "user_pref($1, $2);" | tee -a user.js 
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
