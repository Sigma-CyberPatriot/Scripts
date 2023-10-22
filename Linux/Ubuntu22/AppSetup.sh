#! /bin/bash

function auditSetup {
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
}
