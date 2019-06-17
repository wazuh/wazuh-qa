#!/usr/bin/env python
import os, datetime, time, sys

#Getting install directory
def getOssecConfig(initconf,path):
    if os.path.isfile(path):
        with open(path) as f:
            for line in f.readlines():
                key, value = line.rstrip("\n").split("=")
                initconf[key] = value.replace("\"","")
        if initconf["NAME"] != "Wazuh" or not os.path.exists(initconf["DIRECTORY"]):
            print "Seems like there is no correct Wazuh installation "
            sys.exit(1)
    else:
        print "Seems like there is no Wazuh installation or ossec-init.conf is missing."
        sys.exit(1)

def rootcheckTest(dir, curtime):
    os.system("./feeder.py -L '9:/var/:' 1000")
    time.sleep(.700)
    with open(dir+'/logs/ossec.log','r') as f:
        for line in f:
            linets = datetime.datetime.strptime(line.strip()[:18], '%Y/%m/%d %H:%M:%S')
            if linets > curtime:
                if "socketerr" in line:
                    print("-----------------FAIL-----------------")
                    os.system(dir+'/bin/ossec-control restart')
                    sys.exit(1)
        print("-----------------PASS-----------------")  

if __name__ == "__main__":
    ossec_init = {}
    initconfigpath = "/etc/ossec-init.conf"
    getOssecConfig(ossec_init, initconfigpath)
    print "Analysisd-Rootcheck decoder "
    currentDT = datetime.datetime.now()
    currentDT = currentDT.replace(second=0, microsecond=0)
    rootcheckTest(ossec_init["DIRECTORY"],currentDT)
