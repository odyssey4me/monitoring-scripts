#!/usr/bin/python

#
# Script to determine the health state and various other information
# from a MegaRAID controller.
# https://github.com/odyssey4me/monitoring-scripts
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

# Version required for nagios
VERSION = 'check_megacli v1.0'


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
        # TODO we should not assume that a BBU is present on the adapter
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
        output = {'errorlevel': 0, 'errors': []}

        if self.bbu_state != 'Optimal':
            output['errors'].append('BBU status is %s.' % self.bbu_state)
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 1)

        if self.bbu_state_i2c != 'No':
            output['errors'].append('BBU i2c Errors Detected.')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 1)

        if self.bbu_state_replace == 'Yes':
            output['errors'].append('BBU Battery Replacement required.')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 1)

        if self.bbu_state_no_space != 'No':
            output['errors'].append('BBU has no space to cache offload.')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 1)

        if self.bbu_state_predictive_failure != 'No':
            output['errors'].append('BBU Pack is about to fail & should be replaced.')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 1)

        if self.bbu_state_upgrade_microcode != 'No':
            output['errors'].append('BBU module microcode update required.')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 1)

        if self.bbu_state_capacity_low != 'No':
            output['errors'].append('BBU remaining capacity low.')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 1)

        if self.enclosure_status != 'Normal':
            output['errors'].append('Enclosure status is %s!' % self.enclosure_status)
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 2)

        if self.error_memory_correctable != 0:
            output['errors'].append('Memory Correctable Errors found.')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 1)

        if self.error_memory_uncorrectable != 0:
            output['errors'].append('Memory Uncorrectable Errors found!')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 2)

        return output

    def inventory(self):
        output = {}
        output['ad_%i_product_name' % self.adapter_id] = '%s' % self.product_name
        output['ad_%i_serial_number' % self.adapter_id] = '%s' % self.serial_number
        return output

    def perfdata(self):
        output = {}
        output['ad_%i_bbu_temp' % self.adapter_id] = '%i' % self.bbu_temp
        output['ad_%i_bbu_voltage' % self.adapter_id] = '%i' % self.bbu_voltage
        output['ad_%i_temp_roc' % self.adapter_id] = '%i' % self.temp_roc
        return output


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
        output = {'errorlevel': 0, 'errors': []}

        if self.error_count_media != 0:
            output['errors'].append('Media Errors found!')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 2)

        if self.error_count_other != 0:
            output['errors'].append('Errors found!')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 2)

        if self.error_count_pfc != 0:
            output['errors'].append('Predictive Failures found!')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 2)

        if self.error_smart != 'No':
            output['errors'].append('Drive has flagged a S.M.A.R.T alert!')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 2)

        if self.state == 'Defunct':
            output['errors'].append('Drive is Defunct!')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 2)

        return output

    def inventory(self):
        output = {}
        output['pd_%i_firmware_level' % self.slot_number] = '%s' % self.firmware_level
        output['pd_%i_device_type' % self.slot_number] = '%s' % self.device_type
        output['pd_%i_size_raw' % self.slot_number] = '%i' % self.size_raw
        return output

    def perfdata(self):
        output = {}
        output['pd_%i_temp' % self.slot_number] = '%i' % self.device_temp
        return output


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
        output = {'errorlevel': 0, 'errors': []}

        if self.state == 'Degraded':
            output['errors'].append('Drive is Degraded.')
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 1)
        elif self.state != 'Optimal':
            output['errors'].append('Drive state is %s.' % self.state)
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 2)

        return output

    def inventory(self):
        output = {}
        output['vd_%i_raid_level' % self.disk_id] = '%s' % self.raid_level
        output['vd_%i_size_raw' % self.disk_id] = '%i' % self.size_raw
        output['vd_%i_size_sector' % self.disk_id] = '%i' % self.size_sector
        output['vd_%i_size_strip' % self.disk_id] = '%i' % self.size_strip
        output['vd_%i_num_drives' % self.disk_id] = '%i' % self.num_drives
        output['vd_%i_cache_policy_default' % self.disk_id] = '%s' % self.cache_policy_default
        output['vd_%i_cache_policy_current' % self.disk_id] = '%s' % self.cache_policy_current
        output['vd_%i_cache_policy_disk' % self.disk_id] = '%s' % self.cache_policy_disk
        return output

    def perfdata(self):
        return {}


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('-i', '--inventory', action='store_true', help='Include inventory data in output')
    ap.add_argument('-o', '--output', default='stdout', choices=['stdout', 'nagios', 'zabbix'], help='Output format')
    ap.add_argument('-p', '--perfdata', action='store_true', help='Include performance data in output')
    ap.add_argument('-v', '--verbose', default=0, action='count', help='Verbose output')
    ap.add_argument('-V', '--version', action='store_true', help='Show script version')
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


def set_errorlevel(current, target):
    if current < target != 3:
        return target
    elif target == 3:
        return 3
    else:
        return current


def output_status(item_name, check_type, errorlevel):
    if errorlevel == 0:
        return '%s %s OK' % (item_name, check_type)
    elif errorlevel == 1:
        return '%s %s WARNING' % (item_name, check_type)
    elif errorlevel == 2:
        return '%s %s CRITICAL' % (item_name, check_type)
    else:
        return '%s %s UNKNOWN' % (item_name, check_type)


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


def output_stdout(args):
    adapters = adapter_list()
    errorlevels = []
    for adapter_id in range(0, len(adapters)):

        print output_status('Adapter %i' % adapter_id, 'Health', adapters[adapter_id].health()['errorlevel'])
        errorlevels.append(adapters[adapter_id].health()['errorlevel'])

        if args.verbose > 0:
            for error in adapters[adapter_id].health()['errors']:
                print ' - %s' % error

        if args.perfdata:
            for key, value in adapters[adapter_id].perfdata().iteritems():
                print ' - %s = %s' % (key, value)

        if args.inventory:
            for key, value in adapters[adapter_id].inventory().iteritems():
                print ' - %s = %s' % (key, value)

        virtual_disks = virtual_disk_list(adapter_id)
        for vdisk_id in range(0, len(virtual_disks)):
            print output_status('Virtual Disk %i' % vdisk_id, 'Health', virtual_disks[vdisk_id].health()['errorlevel'])
            errorlevels.append(virtual_disks[vdisk_id].health()['errorlevel'])

            if args.verbose > 0:
                for error in virtual_disks[vdisk_id].health()['errors']:
                    print ' - %s' % error

            if args.perfdata:
                for key, value in virtual_disks[vdisk_id].perfdata().iteritems():
                    print ' - %s = %s' % (key, value)

            if args.inventory:
                for key, value in virtual_disks[vdisk_id].inventory().iteritems():
                    print ' - %s = %s' % (key, value)

        physical_disks = physical_disk_list(adapter_id, adapters[adapter_id].enclosure_id)
        for disk_id in range(0, len(physical_disks)):
            print output_status('Physical Disk %i' % disk_id, 'Health', physical_disks[disk_id].health()['errorlevel'])
            errorlevels.append(physical_disks[disk_id].health()['errorlevel'])

            if args.verbose > 0:
                for error in physical_disks[disk_id].health()['errors']:
                    print ' - %s' % error

            if args.perfdata:
                for key, value in physical_disks[disk_id].perfdata().iteritems():
                    print ' - %s = %s' % (key, value)

            if args.inventory:
                for key, value in physical_disks[disk_id].inventory().iteritems():
                    print ' - %s = %s' % (key, value)

    # filter out 'unknown' errorlevels if there are any 'warning' or 'critical' errorlevels
    if (1 in errorlevels or 2 in errorlevels) and max(errorlevels) == 3:
        errorlevels = filter(lambda item: item != 3, errorlevels)

    sys.exit(max(errorlevels))

def output_nagios(args):
    adapters = adapter_list()
    output_line = ''
    output_perfdata = ' |'
    errorlevels = []
    for adapter_id in range(0, len(adapters)):

        if adapter_id > 0:
            output_line += '; '

        output_line += output_status('Adp%i' % adapter_id, 'Health',
                                     adapters[adapter_id].health()['errorlevel'])
        errorlevels.append(adapters[adapter_id].health()['errorlevel'])

        if args.verbose > 0:
            for error in adapters[adapter_id].health()['errors']:
                output_line += ' %s' % error

        if args.perfdata:
            for key, value in adapters[adapter_id].perfdata().iteritems():
                output_perfdata += " %s='%s'" % (key, value)

        virtual_disks = virtual_disk_list(adapter_id)
        for vdisk_id in range(0, len(virtual_disks)):
            output_line += output_status('; VD%i' % vdisk_id, 'Health',
                                         virtual_disks[vdisk_id].health()['errorlevel'])
            errorlevels.append(virtual_disks[vdisk_id].health()['errorlevel'])

            if args.verbose > 0:
                for error in virtual_disks[vdisk_id].health()['errors']:
                    output_line += ' %s' % error

            if args.perfdata:
                for key, value in virtual_disks[vdisk_id].perfdata().iteritems():
                    output_perfdata += " %s='%s'" % (key, value)

        physical_disks = physical_disk_list(adapter_id, adapters[adapter_id].enclosure_id)
        for disk_id in range(0, len(physical_disks)):
            output_line += output_status('; PD%i' % disk_id, 'Health', physical_disks[disk_id].health()['errorlevel'])
            errorlevels.append(physical_disks[disk_id].health()['errorlevel'])

            if args.verbose > 0:
                for error in physical_disks[disk_id].health()['errors']:
                    output_line += ' %s' % error

            if args.perfdata:
                for key, value in physical_disks[disk_id].perfdata().iteritems():
                    output_perfdata += " %s='%s'" % (key, value)

    if args.perfdata:
        output_line += output_perfdata

    print output_line

    # filter out 'unknown' errorlevels if there are any 'warning' or 'critical' errorlevels
    if (1 in errorlevels or 2 in errorlevels) and max(errorlevels) == 3:
        errorlevels = filter(lambda item: item != 3, errorlevels)

    sys.exit(max(errorlevels))


if __name__ == '__main__':
    args = parse_args()

    try:
        if args.version:
            print VERSION
        elif args.output == 'stdout':
            output_stdout(args)
        elif args.output == 'nagios':
            output_nagios(args)
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