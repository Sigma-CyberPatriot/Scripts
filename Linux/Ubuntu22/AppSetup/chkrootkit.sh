#! /bin/bash

function chkrootkitSetup {
    # Running chkrootkit
    sudo chkrootkit | sudo tee -a /scriptDump/RootKitInfo.txt

    # Making chkrootkit run daily
    sudo echo 'RUN_DAILY="true"' | sudo tee -a /etc/chkrootkit.conf
}