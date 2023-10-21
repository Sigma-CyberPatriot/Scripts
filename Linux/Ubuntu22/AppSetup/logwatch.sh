#! /bin/bash

function logwatchSetup {
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
}