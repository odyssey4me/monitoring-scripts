#!/usr/bin/python

#
# Script to determine the health state and various other information
# from a MegaRAID controller.
#

#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import re
import sys
import argparse
import subprocess
import traceback

# based on using http://hwraid.le-vert.net/wiki/DebianPackages
MEGACLI='/usr/sbin/megacli'

# RAID descriptions returned by megacli are obscure, so we'll convert
# them into more well known descriptions thanks to
# http://globalroot.wordpress.com/2013/06/18/megacli-raid-levels/
RAIDDESC = {
    'Primary-0, Secondary-0, RAID Level Qualifier-0': 'RAID-0',
    'Primary-1, Secondary-0, RAID Level Qualifier-0': 'RAID-1',
    'Primary-5, Secondary-0, RAID Level Qualifier-3': 'RAID-5',
    'Primary-6, Secondary-0, RAID Level Qualifier-3': 'RAID-6',
    'Primary-1, Secondary-3, RAID Level Qualifier-0': 'RAID-10'
}


class PhysicalDisk(object):
    def __init__ (self, diskID):
        self.infoID = diskID
        self.infoEnclosureID = None
        self.infoSlotNumber = None
        self.infoType = None
        self.infoSizeRAW = None
        self.infoFirmwareLevel = None
        self.infoSpeed = None
        self.infoPortSpeed = None
        self.infoTempC = None
        self.errorCountMedia = None
        self.errorCountOther = None
        self.errorCountPFC   = None
        self.errorSMART = None
        self.state = None


class VirtualDisk(object):
    def __init__ (self, diskID):
        self.infoID = diskID
        self.infoAdapterID = None
        self.infoRAID = None
        self.infoSizeRAW = None
        self.infoSizeSector = None
        self.infoSizeStrip = None
        self.infoNumDrives = None
        self.infoCachePolicyDefault = None
        self.infoCachePolicyCurrent = None
        self.infoCachePolicyDisk = None
        self.state = None


class Adapter(object):
    def __init__ (self, infoID):
        self.infoID = infoID
        self.productName = None
        self.serialNumber = None
        self.tempROC = None
        self.errorMemoryCorrectable = None
        self.errorMemoryUncorrectable = None
        self.bbuTemp = None
        self.bbuVoltage = None
        self.bbuCurrent = None
        self.bbuState = None
        self.bbuStateCharge = None
        self.bbuStateVoltage = None
        self.bbuStateTemp = None
        self.bbuStateI2c = None
        self.bbuStateReplace = None
        self.bbuStateCapacityLow = None
        self.bbuStateNoSpace = None
        self.bbuStatePredictiveFailure = None
        self.bbuStateUpgradeMicrocode = None


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--debug', action='store_true',
                    default=False, help='Show debugging output')
    ap.add_argument('-q', '--quiet', action='store_true',
                    default=False, help='Only show error and warning messages')
    return ap.parse_args()


def run_cmd(args):
    args = args.split(' ')
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    status = p.poll()
    output, stderr = p.communicate()
    if not status:
        return output
    else:
        print 'ERROR: %s' % output


def convert_to_bytes(s):
    """
    Based on: http://bit.ly/1fLidGP
    """
    symbols = ('B', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    letter = s[-1:].strip().upper()
    num = float(s[:-1])
    assert isinstance(num,(int,float)) and letter in symbols
    num = float(num)
    prefix = {symbols[0]:1}
    for i, s in enumerate(symbols[1:]):
        prefix[s] = 1 << (i+1)*10
    return int(num * prefix[letter])

def get_pd_info(args):
    output = run_cmd(MEGACLI + ' -PDList -aALL')
    diskList = []
    diskNum = 0
    tmpData = {}
    for line in output.splitlines():

        infoID = re.match('Device Id: ([0-9]+)',line)
        if infoID:
            diskNum = diskNum + 1
            diskList.append(PhysicalDisk(infoID.group(1)))
            diskList[diskNum - 1].infoEnclosureID = tmpData['infoEnclosureID']
            tmpData['infoEnclosureID'] = None
            diskList[diskNum - 1].infoSlotNumber = tmpData['infoSlotNumber']
            tmpData['infoSlotNumber'] = None

        infoEnclosureID = re.match('Enclosure Device ID: ([0-9]+)',line)
        if infoEnclosureID:
            tmpData['infoEnclosureID'] = int(infoEnclosureID.group(1))

        infoSlotNumber = re.match('Slot Number: ([0-9]+)',line)
        if infoSlotNumber:
            tmpData['infoSlotNumber'] = int(infoSlotNumber.group(1))

        infoType = re.match('PD Type: (.+)',line)
        if infoType:
            diskList[diskNum - 1].infoType = infoType.group(1)

        infoSizeRAW = re.match('Raw Size: (.+)B \[.* Sectors\]',line)
        if infoSizeRAW:
            diskList[diskNum - 1].infoSizeRAW = convert_to_bytes(infoSizeRAW.group(1).replace(' ', ''))

        infoFirmwareLevel = re.match('Device Firmware Level: (.+)',line)
        if infoFirmwareLevel:
            diskList[diskNum - 1].infoFirmwareLevel = infoFirmwareLevel.group(1)

        infoSpeed = re.match('Device Speed: (.+)',line)
        if infoSpeed:
            diskList[diskNum - 1].infoSpeed = infoSpeed.group(1).replace(' ', '')

        infoPortSpeed = re.match('Link Speed: (.+)',line)
        if infoPortSpeed:
            diskList[diskNum - 1].infoPortSpeed = infoPortSpeed.group(1).replace(' ', '')

        infoTempC = re.match('Drive Temperature :([0-9]+)C',line)
        if infoTempC:
            diskList[diskNum - 1].infoTempC = int(infoTempC.group(1))

        errorCountMedia = re.match('Media Error Count: ([0-9]+)',line)
        if errorCountMedia:
            diskList[diskNum - 1].errorCountMedia = int(errorCountMedia.group(1))

        errorCountOther = re.match('Other Error Count: ([0-9]+)',line)
        if errorCountOther:
            diskList[diskNum - 1].errorCountOther = int(errorCountOther.group(1))

        errorCountPFC = re.match('Predictive Failure Count: ([0-9]+)',line)
        if errorCountPFC:
            diskList[diskNum - 1].errorCountPFC = int(errorCountPFC.group(1))

        errorSMART = re.match('Drive has flagged a S.M.A.R.T alert : (.+)', line)
        if errorSMART:
            diskList[diskNum - 1].errorSMART = errorSMART.group(1)

        state = re.match('Firmware state: (.+)',line)
        if state:
            diskList[diskNum - 1].state = state.group(1)

    return diskList


def check_pd_health(args):
    diskList = get_pd_info(args)
    output_stdout_alldata(diskList)
    output = ''
    for disk in diskList:
        if disk.errorCountPFC != 0:
            output = output + 'Disk in slot %s has Predictive Failure Count %s\n' % (
                disk.infoSlotNumber, disk.errorCountPFC
            )
        elif disk.state != "Online, Spun Up":
            output = output + 'Disk in slot %s has state %s\n' % (
                disk.infoSlotNumber, disk.state
            )
        elif disk.errorSMART != "No":
            output = output + 'Disk in slot %s has SMART Error Flag %s\n' % (
                disk.infoSlotNumber, disk.errorSMART
            )
        elif disk.errorCountMedia != 0:
            output = output + 'Disk in slot %s has %s Media Errors\n' % (
                disk.infoSlotNumber, disk.errorCountMedia
            )
        elif disk.errorCountOther != 0:
            output += 'Disk in slot %s has %s Other Errors\n' % (
                disk.infoSlotNumber, disk.errorCountOther
            )
        else:
            output += 'Disk in slot %s is healthy\n' % disk.infoSlotNumber
    print output


def get_vd_info(args):
    output = run_cmd(MEGACLI + ' -LdInfo -Lall -aALL')
    diskList = []
    diskNum = 0
    for line in output.splitlines():

        adapterID = re.match('Adapter ([0-9]+) -- Virtual Drive Information:',line)
        if adapterID:
            infoAdapterID = int(adapterID.group(1))

        infoID = re.match('Virtual Drive: ([0-9]+) ',line)
        if infoID:
            diskNum = diskNum + 1
            diskList.append(VirtualDisk(infoID.group(1)))
            diskList[diskNum - 1].infoAdapterID = infoAdapterID

        infoRAID = re.match('RAID Level          : (.+)',line)
        if infoRAID:
            diskList[diskNum - 1].infoRAID = RAIDDESC[infoRAID.group(1)]

        infoSizeRAW = re.match('Size                : (.+)B',line)
        if infoSizeRAW:
            diskList[diskNum - 1].infoSizeRAW = convert_to_bytes(infoSizeRAW.group(1).replace(' ', ''))

        infoSizeSector = re.match('Sector Size         : ([0-9]+)',line)
        if infoSizeSector:
            diskList[diskNum - 1].infoSizeSector = int(infoSizeSector.group(1))

        infoSizeStrip = re.match('Strip Size          : (.+)B',line)
        if infoSizeStrip:
            diskList[diskNum - 1].infoSizeStrip = convert_to_bytes(infoSizeStrip.group(1).replace(' ', ''))

        infoNumDrives = re.match('Number Of Drives    : ([0-9]+)',line)
        if infoNumDrives:
            diskList[diskNum - 1].infoNumDrives = int(infoNumDrives.group(1))

        infoCachePolicyDefault = re.match('Default Cache Policy: (.+)',line)
        if infoCachePolicyDefault:
            diskList[diskNum - 1].infoCachePolicyDefault = infoCachePolicyDefault.group(1)

        infoCachePolicyCurrent = re.match('Current Cache Policy: (.+)',line)
        if infoCachePolicyCurrent:
            diskList[diskNum - 1].infoCachePolicyCurrent = infoCachePolicyCurrent.group(1)

        infoCachePolicyDisk = re.match('Disk Cache Policy   : (.+)',line)
        if infoCachePolicyDisk:
            diskList[diskNum - 1].infoCachePolicyDisk = infoCachePolicyDisk.group(1)

        state = re.match('State               : (.+)',line)
        if state:
            diskList[diskNum - 1].state = state.group(1)

    return diskList


def check_vd_health(args):
    output_stdout_alldata(get_vd_info(args))


def output_stdout_alldata(objectList):
    for obj in objectList:
        colwidth = max(len(key) for key in vars(obj))
        for key in sorted(vars(obj)):
            print key.ljust(colwidth), ':', vars(obj)[key]
        print '---'


def get_bbu_info(adapterObject):
    output = run_cmd(MEGACLI + ' -AdpBbuCmd -a' + str(adapterObject.infoID))
    for line in output.splitlines():

        bbuTemp = re.match('Temperature: ([0-9]+) C',line)
        if bbuTemp:
            adapterObject.bbuTemp = int(bbuTemp.group(1))

        bbuVoltage = re.match('Voltage: ([0-9]+) mV',line)
        if bbuVoltage:
            adapterObject.bbuVoltage = int(bbuVoltage.group(1))

        bbuCurrent = re.match('Current: ([0-9]+) mA',line)
        if bbuCurrent:
            adapterObject.bbuCurrent = int(bbuCurrent.group(1))

        bbuState = re.match('Battery State: (.+)',line)
        if bbuState:
            adapterObject.bbuState = bbuState.group(1)

        bbuStateCharge = re.match('  Charging Status              : (.+)',line)
        if bbuStateCharge:
            adapterObject.bbuStateCharge = bbuStateCharge.group(1)

        bbuStateVoltage = re.match('  Voltage                                 : (.+)',line)
        if bbuStateVoltage:
            adapterObject.bbuStateVoltage = bbuStateVoltage.group(1)

        bbuStateTemp = re.match('  Temperature                             : (.+)',line)
        if bbuStateTemp:
            adapterObject.bbuStateTemp = bbuStateTemp.group(1)

        bbuStateI2c = re.match('  I2c Errors Detected                     : (.+)',line)
        if bbuStateI2c:
            adapterObject.bbuStateI2c = bbuStateI2c.group(1)

        bbuStateReplace = re.match('  Battery Replacement required            : (.+)',line)
        if bbuStateReplace:
            adapterObject.bbuStateReplace = bbuStateReplace.group(1)

        bbuStateCapacityLow = re.match('  Remaining Capacity Low                  : (.+)',line)
        if bbuStateCapacityLow:
            adapterObject.bbuStateCapacityLow = bbuStateCapacityLow.group(1)

        bbuStateNoSpace = re.match('  No space to cache offload               : (.+)',line)
        if bbuStateNoSpace:
            adapterObject.bbuStateNoSpace = bbuStateNoSpace.group(1)

        bbuStatePredictiveFailure = re.match('  Pack is about to fail & should be replaced : (.+)',line)
        if bbuStatePredictiveFailure:
            adapterObject.bbuStatePredictiveFailure = bbuStatePredictiveFailure.group(1)

        bbuStateUpgradeMicrocode = re.match('  Module microcode update required        : (.+)',line)
        if bbuStateUpgradeMicrocode:
            adapterObject.bbuStateUpgradeMicrocode = bbuStateUpgradeMicrocode.group(1)

    return adapterObject


def get_adapter_info(args):
    output = run_cmd(MEGACLI + ' -AdpAllInfo -aALL')
    adapterList = []
    adapterNum = 0
    for line in output.splitlines():

        infoID = re.match('Adapter #([0-9]+)',line)
        if infoID:
            adapterNum = int(infoID.group(1))
            adapterList.append(Adapter(adapterNum))
            adapterList[adapterNum] = get_bbu_info(adapterList[adapterNum])

        productName = re.match('Product Name    : (.+) ',line)
        if productName:
            adapterList[adapterNum].productName = productName.group(1)

        serialNumber = re.match('Serial No       : (.+)',line)
        if serialNumber:
            adapterList[adapterNum].serialNumber = serialNumber.group(1)

        tempROC = re.match('ROC temperature : ([0-9]+)  degree Celsius',line)
        if tempROC:
            adapterList[adapterNum].tempROC = tempROC.group(1)

        errorMemoryCorrectable = re.match('Memory Correctable Errors   : ([0-9]+)',line)
        if errorMemoryCorrectable:
            adapterList[adapterNum].errorMemoryCorrectable = errorMemoryCorrectable.group(1)

        errorMemoryUncorrectable = re.match('Memory Uncorrectable Errors : ([0-9]+)',line)
        if errorMemoryUncorrectable:
            adapterList[adapterNum].errorMemoryUncorrectable = errorMemoryUncorrectable.group(1)

    return adapterList


def check_adapter_health(args):
    output_stdout_alldata(get_adapter_info(args))


def run(args):
    check_pd_health(args)
    check_vd_health(args)
    check_adapter_health(args)

if __name__ == '__main__':
    args = parse_args()

    try:
        run(args)
        sys.exit(0)
    except Exception, err:
        #print("ERROR: %s" % err)
        ex, val, tb = sys.exc_info()
        traceback.print_exception(ex, val, tb)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)