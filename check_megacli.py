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
    output = run_cmd('megacli -PDList -aALL')
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
            output = output + 'Disk in slot %s has %s Other Errors\n' % (
                disk.infoSlotNumber, disk.errorCountOther
            )
        else:
            output = output + 'Disk in slot %s is healthy\n' % disk.infoSlotNumber
    print output


def get_vd_info(args):
    output = run_cmd('megacli -LdInfo -Lall -aALL')
    diskList = []
    diskNum = 0
    tmpData = {}
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
            diskList[diskNum - 1].infoRAID = infoRAID.group(1)

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


def run(args):
    check_pd_health(args)

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
