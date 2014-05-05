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

import re
import sys
import argparse
import subprocess
import traceback

# based on using http://hwraid.le-vert.net/wiki/DebianPackages
MEGACLI = '/usr/sbin/megacli'

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


class Adapter(object):
    def __init__(self, adapter_id):
        # retrieve the adapter information
        megacli_cmd = MEGACLI + ' -AdpAllInfo -a%i -NoLog' % adapter_id
        try:
            output = run_cmd(megacli_cmd)
            self.adapter_id = adapter_id
            for line in output.splitlines():
                product_name = re.match('Product Name    : (.+) ', line)
                if product_name:
                    self.product_name = product_name.group(1)

                serial_number = re.match('Serial No       : (.+)', line)
                if serial_number:
                    self.serial_number = serial_number.group(1)

                temp_roc = re.match('ROC temperature : ([0-9]+)  degree Celsius', line)
                if temp_roc:
                    self.temp_roc = int(temp_roc.group(1))

                error_memory_correctable = re.match('Memory Correctable Errors   : ([0-9]+)', line)
                if error_memory_correctable:
                    self.error_memory_correctable = int(error_memory_correctable.group(1))

                error_memory_uncorrectable = re.match('Memory Uncorrectable Errors : ([0-9]+)', line)
                if error_memory_uncorrectable:
                    self.error_memory_uncorrectable = int(error_memory_uncorrectable.group(1))
        except OSError:
            print 'Failed to get adapter information (%s)' % megacli_cmd

        # retrieve the enclosure information
        # TODO: we should not be assuming that there is only one enclosure per adapter
        megacli_cmd = MEGACLI + ' -EncInfo -a%i -NoLog' % adapter_id
        try:
            output = run_cmd(megacli_cmd)
            for line in output.splitlines():
                enclosure_id = re.match('    Device ID                     : ([0-9]+)', line)
                if enclosure_id:
                    self.enclosure_id = int(enclosure_id.group(1))

                enclosure_slots = re.match('    Number of Slots               : ([0-9]+)', line)
                if enclosure_slots:
                    self.enclosure_slots = int(enclosure_slots.group(1))

                enclosure_status = re.match('    Status                        : (.+)', line)
                if enclosure_status:
                    self.enclosure_status = enclosure_status.group(1)
        except OSError:
            print 'Failed to get enclosure information (%s)' % megacli_cmd

        # retrieve the battery information for the adapter
        megacli_cmd = MEGACLI + ' -AdpBbuCmd -a%i -NoLog' % adapter_id
        try:
            output = run_cmd(megacli_cmd)
            for line in output.splitlines():
                bbu_temp = re.match('Temperature: ([0-9]+) C', line)
                if bbu_temp:
                    self.bbu_temp = int(bbu_temp.group(1))

                bbu_voltage = re.match('Voltage: ([0-9]+) mV', line)
                if bbu_voltage:
                    self.bbu_voltage = int(bbu_voltage.group(1))

                bbu_current = re.match('Current: ([0-9]+) mA', line)
                if bbu_current:
                    self.bbu_current = int(bbu_current.group(1))

                bbu_state = re.match('Battery State: (.+)', line)
                if bbu_state:
                    self.bbu_state = bbu_state.group(1)

                bbu_state_charge = re.match('  Charging Status              : (.+)', line)
                if bbu_state_charge:
                    self.bbu_state_charge = bbu_state_charge.group(1)

                bbu_state_voltage = re.match('  Voltage                                 : (.+)', line)
                if bbu_state_voltage:
                    self.bbu_state_voltage = bbu_state_voltage.group(1)

                bbu_state_temp = re.match('  Temperature                             : (.+)', line)
                if bbu_state_temp:
                    self.bbu_state_temp = bbu_state_temp.group(1)

                bbu_state_i2c = re.match('  I2c Errors Detected                     : (.+)', line)
                if bbu_state_i2c:
                    self.bbu_state_i2c = bbu_state_i2c.group(1)

                bbu_state_replace = re.match('  Battery Replacement required            : (.+)', line)
                if bbu_state_replace:
                    self.bbu_state_replace = bbu_state_replace.group(1)

                bbu_state_capacity_low = re.match('  Remaining Capacity Low                  : (.+)', line)
                if bbu_state_capacity_low:
                    self.bbu_state_capacity_low = bbu_state_capacity_low.group(1)

                bbu_state_no_space = re.match('  No space to cache offload               : (.+)', line)
                if bbu_state_no_space:
                    self.bbu_state_no_space = bbu_state_no_space.group(1)

                bbu_state_predictive_failure = re.match('  Pack is about to fail & should be replaced : (.+)', line)
                if bbu_state_predictive_failure:
                    self.bbu_state_predictive_failure = bbu_state_predictive_failure.group(1)

                bbu_state_upgrade_microcode = re.match('  Module microcode update required        : (.+)', line)
                if bbu_state_upgrade_microcode:
                    self.bbu_state_upgrade_microcode = bbu_state_upgrade_microcode.group(1)
        except OSError:
            print 'Failed to get battery information (%s)' % megacli_cmd

    def health(self):
        # TODO: change health function to return all data required for outputs
        #       - health/status output (include component error if verbosity > 0)
        #       - error level
        #       - performance data output (if --perfdata is specified, in a key-value dict)
        #       - inventory output (if --inventory is specified, in a key-value dict)
        if (self.error_memory_correctable != 0 or self.bbu_state != 'Optimal' or self.bbu_state_i2c != 'No' or
                self.bbu_state_replace == 'Yes' or self.bbu_state_no_space != 'No' or
                self.bbu_state_predictive_failure != 'No' or self.bbu_state_upgrade_microcode != 'No'):
            return 1
        elif self.enclosure_status != 'Normal' or self.error_memory_uncorrectable != 0:
            return 2
        else:
            return 0


class PhysicalDisk(object):
    def __init__(self, adapter_id, enclosure_id, slot_number):
        megacli_cmd = MEGACLI + ' -PDInfo -PhysDrv[%i:%i] -a%i -NoLog' % (enclosure_id, slot_number, adapter_id)
        try:
            output = run_cmd(megacli_cmd)
            self.adapter_id = adapter_id
            self.enclosure_id = enclosure_id
            self.slot_number = slot_number
            for line in output.splitlines():
                device_id = re.match('Device Id: ([0-9]+)', line)
                if device_id:
                    self.device_id = int(device_id.group(1))

                device_type = re.match('PD Type: (.+)', line)
                if device_type:
                    self.device_type = device_type.group(1)

                size_raw = re.match('Raw Size: (.+)B \[.* Sectors\]', line)
                if size_raw:
                    self.size_raw = convert_to_bytes(size_raw.group(1).replace(' ', ''))

                firmware_level = re.match('Device Firmware Level: (.+)', line)
                if firmware_level:
                    self.firmware_level = firmware_level.group(1)

                device_speed = re.match('Device Speed: (.+)', line)
                if device_speed:
                    self.device_speed = device_speed.group(1).replace(' ', '')

                port_speed = re.match('Link Speed: (.+)', line)
                if port_speed:
                    self.port_speed = port_speed.group(1).replace(' ', '')

                device_temp = re.match('Drive Temperature :([0-9]+)C', line)
                if device_temp:
                    self.device_temp = int(device_temp.group(1))

                error_count_media = re.match('Media Error Count: ([0-9]+)', line)
                if error_count_media:
                    self.error_count_media = int(error_count_media.group(1))

                error_count_other = re.match('Other Error Count: ([0-9]+)', line)
                if error_count_other:
                    self.error_count_other = int(error_count_other.group(1))

                error_count_pfc = re.match('Predictive Failure Count: ([0-9]+)', line)
                if error_count_pfc:
                    self.error_count_pfc = int(error_count_pfc.group(1))

                error_smart = re.match('Drive has flagged a S.M.A.R.T alert : (.+)', line)
                if error_smart:
                    self.error_smart = error_smart.group(1)

                state = re.match('Firmware state: (.+)', line)
                if state:
                    self.state = state.group(1)
        except OSError:
            print 'Failed to get physical disk information (%s)' % megacli_cmd

    def health(self):
        if (self.error_count_media != 0 or self.error_count_other != 0 or self.error_count_pfc != 0 or
                self.error_smart != 'No'):
            return 2
        else:
            return 0


class VirtualDisk(object):
    def __init__(self, adapter_id, disk_id):
        megacli_cmd = MEGACLI + ' -LdInfo -L%i -a%i -NoLog' % (disk_id, adapter_id)
        try:
            output = run_cmd(megacli_cmd)
            self.adapter_id = adapter_id
            self.disk_id = disk_id
            for line in output.splitlines():
                raid_level = re.match('RAID Level          : (.+)', line)
                if raid_level:
                    self.raid_level = RAIDDESC[raid_level.group(1)]

                size_raw = re.match('Size                : (.+)B', line)
                if size_raw:
                    self.size_raw = convert_to_bytes(size_raw.group(1).replace(' ', ''))

                size_sector = re.match('Sector Size         : ([0-9]+)', line)
                if size_sector:
                    self.size_sector = int(size_sector.group(1))

                size_strip = re.match('Strip Size          : (.+)B', line)
                if size_strip:
                    self.size_strip = convert_to_bytes(size_strip.group(1).replace(' ', ''))

                num_drives = re.match('Number Of Drives    : ([0-9]+)', line)
                if num_drives:
                    self.num_drives = int(num_drives.group(1))

                cache_policy_default = re.match('Default Cache Policy: (.+)', line)
                if cache_policy_default:
                    self.cache_policy_default = cache_policy_default.group(1)

                cache_policy_current = re.match('Current Cache Policy: (.+)', line)
                if cache_policy_current:
                    self.cache_policy_current = cache_policy_current.group(1)

                cache_policy_disk = re.match('Disk Cache Policy   : (.+)', line)
                if cache_policy_disk:
                    self.cache_policy_disk = cache_policy_disk.group(1)

                state = re.match('State               : (.+)', line)
                if state:
                    self.state = state.group(1)
        except OSError:
            print 'Failed to get virtual disk information (%s)' % megacli_cmd

    def health(self):
        if self.state == 'Degraded':
            return 1
        elif self.state != 'Optimal':
            return 2
        else:
            return 0


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('-i', '--inventory', action='store_true', help='Include inventory data in output')
    ap.add_argument('-o', '--output', default='stdout', choices=['stdout', 'nagios', 'zabbix'], help='Output format')
    ap.add_argument('-p', '--perfdata', action='store_true', help='Include performance data in output')
    ap.add_argument('-v', '--verbose', default=0, action='count', help='Increase output verbosity')
    return ap.parse_args()


def run_cmd(cmd):
    cmd = cmd.split(' ')
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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
    assert isinstance(num, (int, float)) and letter in symbols
    num = float(num)
    prefix = {symbols[0]: 1}
    for i, s in enumerate(symbols[1:]):
        prefix[s] = 1 << (i+1)*10
    return int(num * prefix[letter])


def object_stdout(obj):
    colwidth = max(len(key) for key in vars(obj))
    for key in sorted(vars(obj)):
        print key.ljust(colwidth), ':', vars(obj)[key]


def adapter_list():
    megacli_cmd = MEGACLI + ' -AdpCount -NoLog'
    try:
        output = run_cmd(megacli_cmd)
        adapter_count = 0
        for line in output.splitlines():
            adapter_count_line = re.match('Controller Count: ([0-9]+)\.', line)
            if adapter_count_line:
                adapter_count = int(adapter_count_line.group(1))

        adapter_lst = []

        for adapter_id in range(0, adapter_count):
                    adapter = Adapter(adapter_id)
                    adapter_lst.append(adapter)

        return adapter_lst

    except OSError:
        print 'Failed to get adapter count (%s)' % megacli_cmd
        return []


def physical_disk_list(adapter_id, enclosure_id):
    megacli_cmd = MEGACLI + ' -PdList -a%i -NoLog' % adapter_id
    try:
        output = run_cmd(megacli_cmd)
        disk_list = []
        for line in output.splitlines():
            slot_id_line = re.match('Slot Number: ([0-9]+)', line)
            if slot_id_line:
                slot_id = int(slot_id_line.group(1))
                disk = PhysicalDisk(adapter_id, enclosure_id, slot_id)
                disk_list.append(disk)
        return disk_list
    except OSError:
        print 'Failed to get physical disk list (%s)' % megacli_cmd
        return []


def virtual_disk_list(adapter_id):
    megacli_cmd = MEGACLI + ' -LdInfo -Lall -a%i -NoLog' % adapter_id
    try:
        output = run_cmd(megacli_cmd)
        disk_list = []
        for line in output.splitlines():
            disk_id_line = re.match('Virtual Drive: ([0-9]+) ', line)
            if disk_id_line:
                disk_id = int(disk_id_line.group(1))
                disk = VirtualDisk(adapter_id, disk_id)
                disk_list.append(disk)
        return disk_list
    except OSError:
        print 'Failed to get virtual drive list (%s)' % megacli_cmd
        return []


def output_stdout(verbosity):
    adapters = adapter_list()
    for adapter_id in range(0, len(adapters)):
        if verbosity > 0:
            print '---Adapter %i---' % adapter_id
            object_stdout(adapters[adapter_id])
        if adapters[adapter_id].health() == 0:
            print 'Adapter %i Health OK' % adapter_id
        elif adapters[adapter_id].health() == 1:
            print 'Adapter %i Health WARNING' % adapter_id
        elif adapters[adapter_id].health() == 2:
            print 'Adapter %i Health CRITICAL' % adapter_id
        else:
            print 'Adapter %i Health UNKNOWN' % adapter_id

        virtual_disks = virtual_disk_list(adapter_id)
        for vdisk_id in range(0, len(virtual_disks)):
            if verbosity > 0:
                print '---Virtual Disk %i---' % vdisk_id
                object_stdout(virtual_disks[vdisk_id])
            if virtual_disks[vdisk_id].health() == 0:
                print 'Virtual Disk %i Health OK' % vdisk_id
            elif virtual_disks[vdisk_id].health() == 1:
                print 'Virtual Disk %i Health WARNING' % vdisk_id
            elif virtual_disks[vdisk_id].health() == 2:
                print 'Virtual Disk %i Health CRITICAL' % vdisk_id
            else:
                print 'Virtual Disk %i Health UNKNOWN' % vdisk_id

        physical_disks = physical_disk_list(adapter_id, adapters[adapter_id].enclosure_id)
        for disk_id in range(0, len(physical_disks)):
            if verbosity > 0:
                print '---Physical Disk %i---' % disk_id
                object_stdout(physical_disks[disk_id])
            if physical_disks[disk_id].health() == 0:
                print 'Physical Disk %i Health OK' % disk_id
            elif physical_disks[disk_id].health() == 1:
                print 'Physical Disk %i Health WARNING' % disk_id
            elif physical_disks[disk_id].health() == 2:
                print 'Physical Disk %i Health CRITICAL' % disk_id
            else:
                print 'Physical Disk %i Health PROBLEM' % disk_id


def output_nagios():
    adapters = adapter_list()
    output_line = ''
    output_perfdata = ' |'
    output_error_level = 0
    for adapter_id in range(0, len(adapters)):
        if adapter_id > 0:
            output_line += '; '
        if adapters[adapter_id].health() == 0:
            output_line += 'Ad %i OK' % adapter_id
        elif adapters[adapter_id].health() == 1:
            output_line += 'Ad %i WARNING' % adapter_id
            if output_error_level < 1:
                output_error_level = 1
        elif adapters[adapter_id].health() == 2:
            output_line += 'Ad %i CRITICAL' % adapter_id
            if output_error_level < 2:
                output_error_level = 2
        else:
            output_line += 'Ad %i UNKNOWN' % adapter_id
            if output_error_level == 0:
                output_error_level = 3
        output_perfdata += " 'ad_%i_bbu_temp'=%i" % (adapter_id, adapters[adapter_id].bbu_temp)
        output_perfdata += " 'ad_%i_bbu_voltage'=%i" % (adapter_id, adapters[adapter_id].bbu_voltage)
        output_perfdata += " 'ad_%i_temp_roc'=%i" % (adapter_id, adapters[adapter_id].temp_roc)

        virtual_disks = virtual_disk_list(adapter_id)
        for vdisk_id in range(0, len(virtual_disks)):
            if virtual_disks[vdisk_id].health() == 0:
                output_line += '; VD %i OK' % vdisk_id
            elif virtual_disks[vdisk_id].health() == 1:
                output_line += '; VD %i WARNING' % vdisk_id
                if output_error_level < 1:
                    output_error_level = 1
            elif virtual_disks[vdisk_id].health() == 2:
                output_line += '; VD %i CRITICAL' % vdisk_id
                if output_error_level < 2:
                    output_error_level = 2
            else:
                output_line += '; VD %i UNKNOWN' % vdisk_id
                if output_error_level == 0:
                    output_error_level = 3

        physical_disks = physical_disk_list(adapter_id, adapters[adapter_id].enclosure_id)
        for disk_id in range(0, len(physical_disks)):
            if physical_disks[disk_id].health() == 0:
                output_line += '; PD %i OK' % disk_id
            elif physical_disks[disk_id].health() == 1:
                output_line += '; PD %i WARNING' % disk_id
                if output_error_level < 1:
                    output_error_level = 1
            elif physical_disks[disk_id].health() == 2:
                output_line += '; PD %i CRITICAL' % disk_id
                if output_error_level < 2:
                    output_error_level = 2
            else:
                output_line += '; PD %i UNKNOWN' % disk_id
                if output_error_level == 0:
                    output_error_level = 3
            output_perfdata += " 'pd_%i_temp'=%i" % (disk_id, physical_disks[disk_id].device_temp)

    output_line += output_perfdata
    print output_line
    sys.exit(output_error_level)


if __name__ == '__main__':
    args = parse_args()

    try:
        if args.output == 'stdout':
            output_stdout(args.verbose)
        elif args.output == 'nagios':
            output_nagios()
        elif args.output == 'zabbix':
            # TODO: the zabbix output still needs to be done
            print 'zabbix output'
        sys.exit(0)
    except Exception, err:
        #print("ERROR: %s" % err)
        ex, val, tb = sys.exc_info()
        traceback.print_exception(ex, val, tb)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)