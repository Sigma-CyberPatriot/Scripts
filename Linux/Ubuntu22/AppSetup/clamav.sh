#! /bin/bash

function clamavSetup {
    # Getting sample configuration
    sudo cp /usr/local/etc/clamav/freshclam.conf.sample /usr/local/etc/clamav/freshclam.conf
    sudo cp /usr/local/etc/clamav/clamd.conf.sample /usr/local/etc/clamav/clamd.conf
    
    # Runs the Clam antivirus.
   clamscan -r --remove / > /dev/null
}