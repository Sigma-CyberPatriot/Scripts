#! /bin/bash

function chkrootkitSetup {
    # Running chkrootkit
    sudo chkrootkit >> /scriptDump/RootKitInfo.txt

    # Making chkrootkit run daily
    sudo echo 'RUN_DAILY="true"' >> /etc/chkrootkit.conf
}