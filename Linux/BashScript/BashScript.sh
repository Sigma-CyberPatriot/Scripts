#!/bin/bash
# remember to chmod 755 BashScript from directory.
# To enable line numbers in Emacs, press Alt-X, then type and enter linum-mode
# finish forensics questions before running this. REMEMBER WHAT HAPPENED IN ROUND 2 of CP XII.
# add crontab
# CHECK THE FUCKING CRONJOBS

echo "Starting..."

echo "$(tput setaf 10)------------------------------------"
echo "Securing network settings..."
echo "Enabling firewall..."
sudo apt-get install ufw
sudo apt-get remove iptables-persistent
echo "Configuring UFW..."
#loopback denial
sudo ufw allow in on lo
sudo ufw allow out on lo
sudo ufw deny in from 127.0.0.0/8
sudo ufw deny in from ::1
#
sudo ufw allow ssh
sudo ufw allow http
sudo ufw deny 23
sudo ufw default deny
sudo ufw --force enable
echo "Editing sysctl.conf..."
sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak
# echo "net.ipv6.conf.all.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf
# echo "net.ipv4.icmp_echo_ignore_all=1" | sudo tee -a /etc/sysctl.conf
# sudo sed -i '19,20 s/#//; 25 s/#//; 28 s/#//; 44,45 s/#//; 52 s/#//; 55,56 s/#//; 59 s/#//' /etc/sysctl.conf
sudo cat Desktop/Script/sysctl.conf > /etc/sysctl.conf
echo "Editing host.conf..."
sudo cp /etc/host.conf /etc/host.conf.bak
echo "nospoof on" | sudo tee -a /etc/host.conf
echo "order bind,hosts" | sudo tee -a /etc/host.conf
sudo ip link set dev promisc off 
echo "Done editing network settings."
echo "------------------------------------$(tput sgr0)"


echo "$(tput setaf 9)------------------------------------"
echo "Fixing users..."
function DelUser() {
    VAR1=""
    INP1=""
    echo "Which user do you want to delete? "
    read VAR1
    echo "Are you sure that you want to delete user $VAR1? "
    read INP1
    if [ "$INP1" == "Yes" ] || [ "$INP1" == "yes" ]; then
        sudo userdel $VAR1
    fi
}

function DelGroup() {
    VAR2=""
    INP2=""
    echo "Which group do you want to delete? "
    read VAR2
    echo "Are you sure that you want to delete group $VAR2? "
    read INP2
    if [ "$INP2" == "Yes" ] || [ "$INP2" == "yes" ]; then
        sudo groupdel $VAR2
    fi
}

function AddUser() {
    VAR3=""
    INP3=""
    echo "What is the name of the user you want to add? "
    read VAR3
    echo "Are you sure that you want to add user $VAR3? "
    read INP3
    if [ "$INP3" == "Yes" ] || [ "$INP3" == "yes" ]; then
        sudo adduser $VAR3
    fi
}

function PassChange() {
    VAR4=""
    INP4=""
    echo "Which user's password do you want to change? "
    read VAR4
    echo "Are you sure that you want to change user $VAR4's password? "
    read INP4
    if [ "$INP4" == "Yes" ] || [ "$INP4" == "yes" ]; then
        sudo passwd $VAR4
    fi
}
function PrivChange() {
    VAR5=""
    INP5=""
    echo "Which user's privileges do you want to change? "
    read VAR5
    echo "Are you sure that you want to change user $VAR5's privileges? "
    read INP5
    if [ "$INP5" == "Yes" ] || [ "$INP5" == "yes" ]; then
        usermod -aG sudo $VAR5
    fi
}

echo "Starting user account functions..."
echo "User account list for reference: "
getent passwd
echo "Also a list of sudoers: "
getent group sudo | cut -d: -f4
echo "Also a list of groups: "
getent group

while true
do
    VAR5=""
    AddUser
    echo "Do you want to add another user?"
    read VAR5
    if [ "$VAR5" != "Yes" ] && [ "$VAR5" != "yes" ]; then
        break
    fi
done

while true
do
    VAR5=""
    DelUser
    echo "Do you want to remove another user?"
    read VAR5
    if [ "$VAR5" != "Yes" ] && [ "$VAR5" != "yes" ]; then
        break
    fi
done

while true
do
    VAR5=""
    PassChange
    echo "Do you want to change another password?"
    read VAR5
    if [ "$VAR5" != "Yes" ] && [ "$VAR5" != "yes" ]; then
        break
    fi
done

while true
do
    VAR5=""
    PrivChange
    echo "Do you want to change another user's privileges?"
    read VAR5
    if [ "$VAR5" != "Yes" ] && [ "$VAR5" != "yes" ]; then
        break
    fi
done

while true
do
    VAR5=""
    DelGroup
    echo "Do you want to delete another group?"
    read VAR5
    if [ "$VAR5" != "Yes" ] && [ "$VAR5" != "yes" ]; then
        break
    fi
done

echo "------------------------------------$(tput sgr0)"


echo "$(tput setaf 15)------------------------------------"
echo "Updating..."
echo "basic updates..."
sudo apt-get -qq update
sudo apt-get -qq upgrade
sudo apt-get -qq dist-upgrade
echo "Fixing programs..."
sudo apt-get install firefox
sudo apt-get install thunderbird
sudo apt-get install openssh-server
sudo apt-get install openssl
# Hacking tools
sudo apt-get remove nmap zenmap wireshark
sudo apt-get remove netcat
sudo apt-get remove yersinia
sudo apt-get remove deluge
sudo apt-get remove kismet
sudo apt-get remove hydra
sudo apt-get remove sqlmap
sudo apt-get remove autopsy
sudo apt-get remove ettercap
sudo apt-get remove skipfish
sudo apt-get remove apktool
sudo apt-get remove john-the-ripper
sudo apt-get remove snapd
sudo apt-get remove metasploit-framework
sudo apt-get remove dirb
sudo apt-get remove nikto
sudo apt-get remove aircrack-ng
sudo apt-get remove snort
sudo apt-get remove wifite
sudo apt-get remove rfdump
sudo apt-get remove linuxdcpp
sudo apt-get remove dsniff
sudo apt-get remove fcracklib
sudo apt-get remove httrack
# Games
sudo apt-get remove wesnoth
sudo apt-get remove freeciv endless-sky
sudo apt-get purge gnome-mahjongg gnomine gnome-sudoku aisleriot gnome-mines
# Insecure software
sudo apt-get remove telnet telnetd
sudo apt-get remove nis
sudo apt-get remove rsh-server rsh-client
sudo apt-get remove talk
sudo apt-get remove ldap-utils
sudo apt-get remove manaplus
sudo apt-get remove rsync
sudo apt-get remove rpcbind
# Unnecessary bloatware
sudo apt-get remove cups
sudo apt-get remove isc-dhcp-server
sudo apt-get remove dovecot-imapd dovecot-pop3d
sudo apt-get remove squid
sudo apt-get remove xserver-xorg*
sudo apt-get remove slapd
sudo apt-get remove bind9
sudo apt-get purge atd
sudo apt-get remove avahi-daemon avahi-utils
sudo apt-get purge zeitgeist-core zeitgeist-datahub python-zeitgeist rhythmbox-plugin-zeitgeist zeitgeist
sudo apt-get purge nfs-kernel-server nfs-common portmap rpcbind autofs
sudo apt-get purge apport

while (true)
do
    VAR6=""
    echo "Do you want to remove Apache2? (yes or no)"
    read VAR6
    if [ "$VAR6" == "Yes" ] || [ "$VAR6" == "yes" ]; then
        sudo apt-get remove apache2
        break
    elif [ "$VAR6" == "No" ] || [ "$VAR6" == "no" ]; then
        sudo chmod +x ./ApacheScript.sh
        sudo bash ApacheScript.sh
        break
    fi
done

while (true)
do
    VAR7=""
    echo "Do you want to remove nginx? (yes or no)"
    read VAR7
    if [ "$VAR7" == "Yes" ] || [ "$VAR7" == "yes" ]; then
        sudo apt-get remove nginx
        break
    elif [ "$VAR7" == "No" ] || [ "$VAR7" == "no" ]; then
        sudo chmod +x ./NginxScript.sh
        sudo bash NginxScript.sh
        break
    fi
done

while (true)
do
    VAR11=""
    echo "Do you want to remove samba? (yes or no)"
    read VAR11
    if [ "$VAR11" == "Yes" ] || [ "$VAR11" == "yes" ]; then
        sudo apt-get remove samba
        break
    elif [ "$VAR11" == "No" ] || [ "$VAR11" == "no" ]; then
        sudo chmod +x ./SambaScript.sh
        sudo bash SambaScript.sh
        break
    fi
done

# No PostGreScript?
while (true)
do
    VAR12=""
    echo "Do you want to remove postgresql? (yes or no)"
    read VAR12
    if [ "$VAR12" == "Yes" ] || [ "$VAR12" == "yes" ]; then
        sudo apt-get remove postgresql
        break
    elif [ "$VAR12" == "No" ] || [ "$VAR12" == "no" ]; then
        sudo chmod +x ./PostGreScript.sh
        sudo bash PostGreScript.sh
        break
    fi
done

while (true)
do
    VAR8=""
    echo "Do you want to remove FTP? (yes or no)"
    read VAR8
    if [ "$VAR8" == "Yes" ] || [ "$VAR8" == "yes" ]; then
        echo "Removing all versions of FTP..."
        sudo apt-get purge ftp
        sudo apt-get purge pure-ftpd
        sudo apt-get purge lftp
        sudo apt-get purge tftp
        sudo apt-get purge gftp
        sudo apt-get purge jftp
        sudo apt-get purge proftpd
        sudo apt-get purge vsftpd
        break
    elif [ "$VAR8" == "No" ] || [ "$VAR8" == "no" ]; then
        array=(1 2 3 4 5 6 7 8 9 10)
        echo "Which version(s) of FTP do you want to keep?"
        echo "1. FTP"
        echo "2. Pure-FTPD"
        echo "3. LFTP"
        echo "4. TFTP"
        echo "5. GFTP"
        echo "6. JFTP"
        echo "7. Pro-FTPD"
        echo "8. VSFTPD"
        echo "9. TNFTP"
        echo "10. BareFTP"
        while (true)
        do
            VAR9=""
            echo "Enter a number (enter anything else to escape)."
            read VAR9
            echo VAR9
            if [ "$VAR9" != 1 ] && [ "$VAR9" != 2 ] && [ "$VAR9" != 3 ] && [ "$VAR9" != 4 ] && [ "$VAR9" != 5 ] && [ "$VAR9" != 6 ] && [ "$VAR9" != 7 ] && [ "$VAR9" != 8 ] && [ "$VAR9" != 9 ] && [ "$VAR9" != 10 ]; then
                break
            fi
            array=( "${array[@]/$VAR9}" )
        done
        for i in "${array[@]}";
        do
            if [ "$i" == 1 ]; then
                echo "Removing FTP..."
                sudo apt-get remove ftp
            elif [ "$i" == 2 ]; then
                echo "Removing Pure-FTPD..."
                sudo apt-get remove pure-ftpd
            elif [ "$i" == 3 ]; then
                echo "Removing LFTP..."
                sudo apt-get remove lftp
            elif [ "$i" == 4 ]; then
                echo "Removing TFTP..."
                sudo apt-get remove tftp
            elif [ "$i" == 5 ]; then
                echo "Removing GFTP..."
                sudo apt-get remove gftp
            elif [ "$i" == 6 ]; then
                echo "Removing JFTP..."
                sudo apt-get remove jftp
            elif [ "$i" == 7 ]; then
                echo "Removing Pro-FTPD..."
                sudo apt-get remove proftpd
            elif [ "$i" == 8 ]; then
                echo "Removing VSFTPD..."
                sudo apt-get remove vsftpd
            elif [ "$i" == 9 ]; then
                echo "Removing TNFTP..."
                sudo apt-get remove vsftpd
            elif [ "$i" == 190 ]; then
                echo "Removing BareFTP..."
                sudo apt-get remove vsftpd
        fi
    done
        break
    fi
done

echo "installing antiviruses..."
sudo apt-get install clamav
sudo clamscan -r --remove /
sudo apt-get install rkhunter
sudo apt-get install chkrootkit
sudo apt-get install logwatch libdate-manip-perl
sudo apt-get autoremove
echo "------------------------------------ $(tput sgr0)"


echo "$(tput setaf 2)------------------------------------"
# Command to find all non-root files: sudo find / ! -user root -not -path "/proc/*" -not -path "*/.cache/*" -not -path "/usr/src/*" -not -path "/var/*" -not -path "/tmp/*" -not -path "/run/*" -not -path "*/.local/*"
echo "Deleting unauthorized files..."
sudo find / -type f -name '*.jpg' -delete
sudo find / -type f -name '*.mp3' -delete
sudo find / -type f -name '*.avi' -delete
sudo find / -type f -name '*.mov' -delete
sudo find / -type f -name '*.pdf' -delete
sudo find / -type f -name '*.ps1' -delete
sudo find / -type f -name '*.bat' -delete
sudo find / -type f -name '*.flac' -delete
sudo find / -type f -name '*.aac' -delete
sudo find / -type f -name '*.tiff' -delete
sudo find / -type f -name '*.mp4' -delete
sudo find / -type f -name '*.RAW' -delete
sudo find / -type f -name '*.flv' -delete
sudo find / -type f -name '*.exe' -delete
sudo find / -type f -name '*.vbs' -delete
sudo find / -type f -name '*.shosts' -delete
sudo find / -type f -name '*.3gp' -delete
sudo find / -type f -name '*.msi' -delete
sudo find / -type f -name '*.dll' -delete
echo "------------------------------------ $(tput sgr0)"


echo "------------------------------------"
echo "Fixing config files..."
echo "opening login defs... Remember to set:
    max age: 90, 
    min age: 7, 
    warn age: 14
    login retries: 3
    login timeout: 30
"
sleep 5
sudo nano /etc/login.defs
echo "opening ssh defs .... Remember to set:
    PermitRootLogin no
    PermitUserEnvironment no
    PermitEmptyPasswords no
    Protocol 2
    PrintLastLog no
    PubkeyAuthentication yes
    RSAAuthentication yes
    LoginGraceTime 30
    ClientAliveInterval 600
    ClientAliveCountMax 1
    UsePAM yes
    UsePrivilegeSeparation yes
    StrictModes yes
    IgnoreUserKnownHosts yes
    IgnoreRhosts yes
    RhostsAuthentication no
    RhostsRSAAuthentication no
    HostBasedAuthentication no
    AllowTcpForwarding no
    X11Forwarding no
    LogLevel VERBOSE
    Port 2453

    If any of these settings are missing, just add it to the bottom.
    If you mistype any of these and sshd won't start, just type sshd --t to find the line.
"
sleep 5
sudo nano /etc/ssh/sshd_config
echo "Remember the following password settings: 
    deny=10
    difok=3
    minlen=8
    remember=5
    unlock_time=1800
    ucredit=-1
    lcredit=-1
    dcredit=-1
    ocredit=-1
    maxrepeat=2
    dictcheck=1
"
sleep 5
echo "opening common auth. create a new line called tally2.so and add 'deny=10 unlock_time=1800'"
sleep 5
sudo nano /etc/pam.d/common-auth
echo "opening common password. add minlen=8 and remember=5 to pam_unix.so line. add 'ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-' to pam_cracklib.so."
sleep 5
sudo apt-get install libpam-cracklib
sudo nano /etc/pam.d/common-password
sudo cp /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.bak
sudo del /etc/lightdm/lightdm.conf
sudo touch /etc/lightdm/lightdm.conf
echo "[SeatDefaults]" | sudo tee -a /etc/lightdm/lightdm.conf
echo "user-session=ubuntu" | sudo tee -a /etc/lightdm/lightdm.conf
echo "greeter-session=unity-greeter" | sudo tee -a /etc/lightdm/lightdm.conf
echo "allow-guest=false" | sudo tee -a /etc/lightdm/lightdm.conf
#
#    Note: If lightdm bricks itself again:
#       * Press Ctrl-alt-F1 through F7 on loading screen.
#       * When in terminal, login to sudoer account and reinstall lightdm.
#           * If LightDM won't install, check /etc/apt-get/sources.list. Full version here: https://gist.github.com/rohitrawat/60a04e6ebe4a9ec1203eac3a11d4afc1
#       * After that, reboot the PC and it should work
#
echo "Disabling root password... add 'Defaults     rootpw' to defaults section..."
echo "Remember to set the su password to something else before doing this."
sudo visudo
#
#    Note: If you lock yourself out by not setting a root password:
#       * First, reboot your computer and enter the boot menu by pressing F2 upon boot.
#       * Second, go into advanced settings and enter the root settings page.
#       * Demount and remount the root disk.
#       * Then, you can set a root password and continue with the boot process.
#       * For further information: https://phoenixnap.com/kb/how-to-change-root-password-linux
#
# sudo passwd -l root 
echo "------------------------------------"


echo "------------------------------------"
echo "Fixing permissions..."
sudo chmod 000 /etc/shadow
sudo chmod 644 /etc/passwd
sudo chmod 600 /etc/ssh/ssh_host*key
sudo chmod 600 /etc/ssh/*key.pub
sudo chmod 640 /var/log 
sudo chmod 640 /var/log/syslog
sudo chown syslog /var/log/syslog
sudo chown root /var/log
sudo chgrp adm /var/log/syslog 


sudo chmod 755 /bin
sudo chmod 755 /sbin
sudo chmod 755 /usr/bin
sudo chmod 755 /usr/sbin
sudo chmod 755 /usr/local/bin
sudo chmod 755 /usr/local/sbin
echo "------------------------------------"

echo "------------------------------------"
echo "Enabling auditing policy..."
sudo apt-get install auditd augenrules
sudo su
sudo cat Desktop/Script/audit.rules > /etc/audit/rules.d/audit.rules
exit
sudo augenrules --load
sudo apt-get install rsyslog
sudo systemctl enable rsyslog
sudo systemctl restart rsyslog
echo "------------------------------------"

echo "$(tput setaf 3)------------------------------------"
echo "Fixing firefox settings..."
cd ~
cd ~/.mozilla/firefox/*.default
sudo touch user.js
function FirefoxPref() {
    echo "user_pref($1, $2);" | sudo tee -a user.js
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
cd ~
echo "------------------------------------ $(tput sgr0)"


echo "$(tput setaf 14)------------------------------------"
echo "Experimental stuff..."
sudo systemctl mask ctrl-alt-del.target
sudo systemctl disable kdump.service

echo "Testing for shellshock vulnerabilities..."
echo "If the system is vulnerable to CVE-2014-6271, it should print 'vulnerable this is a test'"
env x='() { :;}; echo vulnerable' bash -c "echo this is a test" 
echo "If the system is vulnerable to CVE-2014-7169, it should throw a syntax error"
env X='() { (a)=>\' sh -c "echo date"; cat echo; rm ./echo
echo "If the system is vulnerable to CVE-2014-6277 or 6278, it should print 'not patched'"
foo='() { echo not patched; }' bash -c foo
echo "If the system is vulnerable to CVE-2014-7186, it should throw a syntax error"
bash -c "export f=1 g='() {'; f() { echo 2;}; export -f f; bash -c 'echo \$f \$g; f; env | grep ^f='" 
echo "If the system is vulnerable CVE-2014-7187, it should print 'CVE2014-7187 vulnerable, word_lineno'"
(for x in {1..200} ; do echo "for x$x in ; do :"; done; for x in {1..200} ; do echo done ; done) | bash || echo "CVE-2014-7187 vulnerable, word_lineno" 

echo "Disabling unessecary services..."
sudo apt-get install bum
sudo bum

echo "Setting process ID limits..."
sudo nano /etc/security/limits.conf

echo "Checking for open ports..."
sudo netstat -tulpna
while (true)
do
    VAR10 = 0
    VAR11 = ""
    echo "What port do you want to close?"
    read VAR10
    sudo ufw deny VAR10
    echo "Do you want to close another port?"
    read VAR11
    if [ "$VAR11" != "Yes" ] || [ "$VAR11" != "yes" ]; then
        break
    fi
done

echo "Scanning for suspicious cron jobs..."
echo "Printing out all user cron jobs..."
for filename in /var/spool/cron/crontabs; do
    sudo cat "$filename"
done
echo "Printing out all root cron jobs..."
sudo cat /etc/crontab

echo "... script has finished."
echo "------------------------------------ $(tput sgr0)"


# if rm is not working
# chattr -a -i
# then chmod -ug+w
# then delete

#postgresql check /etc/postgresql
# turn ssl on and check for mapping

# samba change protocol to not lanman1


# Some urls:
#    https://www.thefanclub.co.za/how-to/how-secure-ubuntu-1604-lts-server-part-1-basics
#    https://github.com/Forty-Bot/linux-checklist
#    https://pastebin.com/NS4ng79h
#    https://www.stigviewer.com/stig/canonical_ubuntu_16.04_lts/
#    https://stigviewer.com/stig/canonical_ubuntu_18.04_lts/
#    https://sites.google.com/site/cyberpatriotkhs/hardening-check-list-1
#    http://bookofzeus.com/harden-ubuntu/
#    Logs and their meaning: http://bookofzeus.com/harden-ubuntu/monitoring-tools/watch-logs/
#    https://stigviewer.com/stig/canonical_ubuntu_18.04_lts/2020-09-10/finding/V-219185
#    https://www.cisecurity.org/cis-benchmarks/