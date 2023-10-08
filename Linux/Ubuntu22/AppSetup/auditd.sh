#! /bin/bash

function auditdSetup {
    sudo systemctl --now enable auditd
    sudo augenrules --load
    sudo echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf

    # Time Rules
    sudo echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/time.rules
    sudo echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/time.rules
    sudo echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/time.rules
    sudo echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/time.rules
    sudo echo "wa -k time-change" >> /etc/audit/rules.d/time.rules

    # System Locale Rules
    sudo echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/system-locale.rules
    sudo echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/system-locale.rules
    sudo echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
    sudo echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
    sudo echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
    sudo echo "-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules

    # Identity Rules
    sudo echo "-w /etc/group -p wa -k identity" >> /etc/audit/rules.d/identity.rules
    sudo echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/identity.rules
    sudo echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/identity.rules
    sudo echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/identity.rules
    sudo echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/identity.rules

    # Login Rules
    sudo echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/rules.d/logins.rules
    sudo echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/logins.rules
    sudo echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/logins.rules

    # Permissions Rules
    sudo echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/permissions.rules
    sudo echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/permissions.rules
    sudo echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/permissions.rules
    sudo echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/permissions.rules
    sudo echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/permissions.rules
    sudo echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/permissions.rules

    # File Change Rules
    sudo echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/file-change.rules
    sudo echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/file-change.rules

    # Scope Rules
    sudo echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/scope.rules
    sudo echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/scope.rules

    # Sudo Rules
    sudo echo "-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions" >> /etc/audit/rules.d/sudo.rules
    sudo echo "-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions" >> /etc/audit/rules.d/sudo.rules

    # Module Rules
    sudo echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/rules.d/modules.rules
    sudo echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/modules.rules
    sudo echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/modules.rules
    sudo echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/modules.rules

    # Reloading audit config
    sudo auditctl -e 1 /etc/audit/rules.d/time.rules
    sudo auditctl -e 1 /etc/audit/rules.d/system-locale.rules
    sudo auditctl -e 1 /etc/audit/rules.d/identity.rules
    sudo auditctl -e 1 /etc/audit/rules.d/logins.rules
    sudo auditctl -e 1 /etc/audit/rules.d/permissions.rules
    sudo auditctl -e 1 /etc/audit/rules.d/file-change.rules
    sudo auditctl -e 1 /etc/audit/rules.d/scope.rules
    sudo auditctl -e 1 /etc/audit/rules.d/sudo.rules
    sudo auditctl -e 1 /etc/audit/rules.d/modules.rules
}