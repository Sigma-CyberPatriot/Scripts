#! /bin/bash

function sshSetup {
    sshd -t -f /etc/ssh/sshd_config

    echo "Banner /etc/issue.net" | tee -a /etc/ssh/sshd_config

    systemctl restart sshd.service

    # chmod 600 /etc/ssh/ssh_host*key #>/dev/null 2>&1
    # chmod 600 /etc/ssh/*key.pub #>/dev/null 2>&1

    # Editing sshd_config to set too many things to count.
    echo "PermitRootLogin no"         | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "PermitUserEnvironment no"   | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "PermitEmptyPasswords no"    | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "Protocol 2"                 | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "PrintLastLog no"            | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "PubkeyAuthentication yes"   | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "RSAAuthentication yes"      | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "LoginGraceTime 30"          | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "ClientAliveInterval 600"    | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "ClientAliveCountMax 1"      | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "UsePAM yes"                 | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "UsePrivilegeSeparation yes" | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "StrictModes yes"            | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "IgnoreUserKnownHosts yes"   | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "IgnoreRhosts yes"           | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "RhostsAuthentication no"    | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "RhostsRSAAuthentication no" | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "HostBasedAuthentication no" | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "AllowTcpForwarding no"      | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "X11Forwarding no"           | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "LogLevel VERBOSE"           | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
    echo "Port 2453"                  | tee -a /etc/ssh/sshd_config #>/dev/null 2>&1
}