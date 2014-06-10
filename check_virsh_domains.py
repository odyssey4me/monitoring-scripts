#!/usr/bin/python

#
# Script to determine the performance statistics and other information
# related to libvirt guests
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
import socket
import libvirt
import argparse
import traceback
import jsonpickle
import subprocess
from xml.etree import ElementTree

# Version required for nagios
VERSION = 'check_virsh_domains v1.0'

# Convert the Domain State integer into the description
# http://libvirt.org/html/libvirt-libvirt.html#virDomainState
DOMAIN_STATES = {
    0: 'None',
    1: 'Running',
    2: 'Blocked on resource',
    3: 'Paused by user',
    4: 'Being shut down',
    5: 'Shut off',
    6: 'Crashed',
    7: 'Suspended by guest power management'
}

# Location of Zabbix Agent Configuration file
# TODO: This really should either be found, or be an optional argument
ZABBIX_CONF = '/opt/zabbix/etc/zabbix_agentd.conf'

# Location of the zabbix_sender binary
# TODO: This really should either be found, or be an optional argument
ZABBIX_SENDER = '/opt/zabbix/bin/zabbix_sender'


class Domain(object):
    def __init__(self, vir_dom):
        try:
            # Get the domain's network interface device list
            if_devices = self.get_if_devices(vir_dom)

            # Get the domain's block device list
            blk_devices = self.get_blk_devices(vir_dom)

            # Get the domain's information
            dom_info = vir_dom.info()

            # Get the domain's memory stats
            mem_stats = vir_dom.memoryStats()

            # Get the domain's UUID
            self.uuid = vir_dom.UUIDString()

            # Compile the network interface stats for each network interface device
            for if_num, if_dev in enumerate(if_devices):
                # Get the interface stats
                if_stats = vir_dom.interfaceStats(if_dev)

                # Set class attributes using the interface index number (not the name)
                setattr(self, 'if_%s_rx_bytes' % if_num, int(if_stats[0]))
                setattr(self, 'if_%s_rx_packets' % if_num, int(if_stats[1]))
                setattr(self, 'if_%s_rx_errors' % if_num, int(if_stats[2]))
                setattr(self, 'if_%s_rx_drop' % if_num, int(if_stats[3]))
                setattr(self, 'if_%s_tx_bytes' % if_num, int(if_stats[4]))
                setattr(self, 'if_%s_tx_packets' % if_num, int(if_stats[5]))
                setattr(self, 'if_%s_tx_errors' % if_num, int(if_stats[6]))
                setattr(self, 'if_%s_tx_drop' % if_num, int(if_stats[7]))

            # Compile the block device stats for each block device
            for blk_dev in blk_devices:
                #Get the block device stats
                blk_stats = vir_dom.blockStats(blk_dev)

                # Set class attributes using the device name
                setattr(self, 'blk_%s_rd_req' % blk_dev, int(blk_stats[0]))
                setattr(self, 'blk_%s_rd_bytes' % blk_dev, int(blk_stats[1]))
                setattr(self, 'blk_%s_wr_req' % blk_dev, int(blk_stats[2]))
                setattr(self, 'blk_%s_wr_bytes' % blk_dev, int(blk_stats[3]))

            # Get the memory stats in kB and covert to B for consistency
            self.mem_max_bytes = int(dom_info[1]) * 1024
            self.mem_used_bytes = int(dom_info[2]) * 1024

            # Get the number of vCPU's and the usage time in nanoseconds
            self.cpu_count = int(dom_info[3])
            self.cpu_time = int(dom_info[4])

            # Get the state of the domain
            self.state = DOMAIN_STATES[dom_info[0]]

            # Note:
            # To calculate %CPU utilization you need to have a time period. We're expecting that the
            # %CPU calculation is done externally by a system that knows the time period between measurements.
            #
            # For reference:
            # http://people.redhat.com/~rjones/virt-top/faq.html#calccpu
            # cpu_time_diff = cpuTime_now - cpuTime_t_seconds_ago
            # %CPU = 100 * cpu_time_diff / (t * host_cpus * 10^9)

            # There may not be anything in mem_stats (support is limited), but let's add any values there may be
            for key, value in mem_stats.iteritems():
                value_bytes = int(value) * 1024
                setattr(self, 'mem_%s' % key, value_bytes)

        except OSError:
            print 'Failed to get domain information'

    def get_if_devices(self, vir_dom):
        #Function to return a list of network devices used

        #Create a XML tree from the domain XML description
        dom_tree = ElementTree.fromstring(vir_dom.XMLDesc(0))

        #The list of device names
        devices = []

        #Iterate through all network interface target elements of the domain
        for target in dom_tree.findall("devices/interface/target"):
            #Get the device name
            dev = target.get("dev")

            #If this device is already in the list, don't add it again
            if not dev in devices:
                devices.append(dev)

        #Completed device name list
        return devices

    def get_blk_devices(self, vir_dom):
        #Function to return a list of block devices used

        #Create a XML tree from the domain XML description
        dom_tree = ElementTree.fromstring(vir_dom.XMLDesc(0))

        #The list of device names
        devices = []

        #Iterate through all network interface target elements of the domain
        for target in dom_tree.findall("devices/disk/target"):
            #Get the device name
            dev = target.get("dev")

            #If this device is already in the list, don't add it again
            if not dev in devices:
                devices.append(dev)

        #Completed device name list
        return devices

    def health(self):
        output = {'errorlevel': 0, 'errors': []}

        # Check whether there are network interface errors or drops
        for key in vars(self):
            if re.match('if_.*_errors', key):
                if vars(self)[key] > 0:
                    output['errors'].append('Domain has network interface errors.')
                    output['errorlevel'] = set_errorlevel(output['errorlevel'], 1)
            if re.match('if_.*_drop', key):
                if vars(self)[key] > 0:
                    output['errors'].append('Domain has network interface drops.')
                    output['errorlevel'] = set_errorlevel(output['errorlevel'], 1)

        # Check whether the domain is in a 'blocked' or 'crashed' state
        if self.state == 'Blocked on resource' or self.state == 'Crashed':
            output['errors'].append('Domain is %s!' % self.state)
            output['errorlevel'] = set_errorlevel(output['errorlevel'], 2)

        return output

    def inventory(self):
        output = {}
        output['mem_max_bytes'] = '%i' % self.mem_max_bytes
        output['cpu_count'] = '%i' % self.cpu_count
        output['state'] = '%s' % self.state
        output['uuid'] = '%s' % self.uuid
        return output

    def perfdata(self):
        output = {}

        # Loop through all attributes and add the if and blk data
        for key in vars(self):
            if re.match('if_.*', key) or re.match('blk_.*', key):
                output[key] = vars(self)[key]

        output['mem_used_bytes'] = self.mem_used_bytes
        output['cpu_time'] = self.cpu_time

        return output


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--discovery', action='store_true', help='Only output discovery data')
    ap.add_argument('-i', '--inventory', action='store_true', help='Include inventory data in output')
    ap.add_argument('-o', '--output', default='stdout', choices=['stdout', 'nagios', 'zabbix'], help='Output format')
    ap.add_argument('-p', '--perfdata', action='store_true', help='Include performance data in output')
    ap.add_argument('-v', '--verbose', default=0, action='count', help='Verbose output')
    ap.add_argument('-V', '--version', action='store_true', help='Show script version')
    return ap.parse_args()


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


def output_stdout(args):
    domains = domain_list()
    errorlevels = []
    for domain in domains:

        print output_status('Domain %s' % domain.uuid, 'Health', domain.health()['errorlevel'])
        errorlevels.append(domain.health()['errorlevel'])

        if args.verbose > 0:
            for error in domain.health()['errors']:
                print ' - %s' % error

        if args.perfdata:
            for key, value in domain.perfdata().iteritems():
                print ' - %s = %s' % (key, value)

        if args.inventory:
            for key, value in domain.inventory().iteritems():
                print ' - %s = %s' % (key, value)

    # filter out 'unknown' errorlevels if there are any 'warning' or 'critical' errorlevels
    if (1 in errorlevels or 2 in errorlevels) and max(errorlevels) == 3:
        errorlevels = filter(lambda item: item != 3, errorlevels)

    sys.exit(max(errorlevels))


def output_nagios(args):
    domains = domain_list()
    output_line = ''
    output_perfdata = ' |'
    errorlevels = []
    for domain in domains:

        if output_line != '':
            output_line += '; '

        output_line += output_status('Dom %s' % domain.uuid, 'Health',
                                     domain.health()['errorlevel'])
        errorlevels.append(domain.health()['errorlevel'])

        if args.verbose > 0:
            for error in domain.health()['errors']:
                output_line += ' %s' % error

        if args.perfdata:
            for key, value in domain.perfdata().iteritems():
                output_perfdata += " %s='%s'" % (key, value)

    if args.perfdata:
        output_line += output_perfdata

    print output_line

    # filter out 'unknown' errorlevels if there are any 'warning' or 'critical' errorlevels
    if (1 in errorlevels or 2 in errorlevels) and max(errorlevels) == 3:
        errorlevels = filter(lambda item: item != 3, errorlevels)

    sys.exit(max(errorlevels))


def output_zabbix(args):
    domains = domain_list()
    output_line = ''
    errorlevels = []
    for domain in domains:

        output_line += '%s virsh.domain[%s,health] %s\n' % (socket.gethostname(), domain.uuid, output_status(domain.uuid,'Health', domain.health()['errorlevel']))
        errorlevels.append(domain.health()['errorlevel'])

        if args.verbose > 0 and len(domain.health()['errors']) > 0:
            output_line += '%s virsh.domain[%s,errors] %s\n' % (socket.gethostname(), domain.uuid, ";".join(domain.health()['errors']))
        elif args.verbose > 0 and len(domain.health()['errors']) == 0:
            output_line += '%s virsh.domain[%s,errors] None\n' % (socket.gethostname(), domain.uuid)

        if args.perfdata:
            for key, value in domain.perfdata().iteritems():
                output_line += '%s virsh.domain[%s,%s] %s\n' % (socket.gethostname(), domain.uuid, key, value)

        if args.inventory:
            for key, value in domain.inventory().iteritems():
                output_line += '%s virsh.domain[%s,%s] %s\n' % (socket.gethostname(), domain.uuid, key, value)

    # filter out 'unknown' errorlevels if there are any 'warning' or 'critical' errorlevels
    if (1 in errorlevels or 2 in errorlevels) and max(errorlevels) == 3:
        errorlevels = filter(lambda item: item != 3, errorlevels)

    #TODO: This should really have exception handling
    cmd = '%s -c %s -v -i -' % (ZABBIX_SENDER, ZABBIX_CONF)
    cmd = cmd.split(' ')
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p.stdin.write(output_line)
    status = p.poll()
    stdout, stderr = p.communicate()
    if not status:
        print 'zabbix_sender output: %s' % stdout
    else:
        print 'zabbix_sender error: %s' % stdout

    print output_status('Overall','Health', max(errorlevels))
    sys.exit(max(errorlevels))


def output_zabbix_discovery(args):
    #TODO: Sort this mess out.
    #Using the objects was too slow - the discovery would keep failing when requested by the Zabbix Server
    try:
        # Connect to the local hypervisor (read only)
        conn = libvirt.openReadOnly(None)

        # Prepare the lists and dict objects
        dom_list = []
        return_dict = {}

        # Loop through the running domains and retrieve the appropriate discovery information
        for dom_id in conn.listDomainsID():
            dom_dict = {}
            vir_dom = conn.lookupByID(dom_id)
            dom_dict['{#VIRSH_DOMAIN_UUID}'] = vir_dom.UUIDString()

            if args.perfdata:
                dom_tree = ElementTree.fromstring(vir_dom.XMLDesc(0))

                #The list of device names
                if_devices = []

                #Iterate through all network interface target elements of the domain
                for target in dom_tree.findall("devices/interface/target"):
                    #Get the device name
                    dev = target.get("dev")

                    #If this device is already in the list, don't add it again
                    if not dev in if_devices:
                        if_devices.append(dev)

                #Put the final device list into the domain's return dict
                for if_num, if_dev in enumerate(if_devices):
                    dom_dict['{#VIRSH_DOMAIN_NIC}'] = str(if_num)

                #The list of device names
                blk_devices = []

                #Iterate through all network interface target elements of the domain
                for target in dom_tree.findall("devices/disk/target"):
                    #Get the device name
                    dev = target.get("dev")

                    #If this device is already in the list, don't add it again
                    if not dev in blk_devices:
                        blk_devices.append(dev)

                #Put the final device list into the domain's return dict
                for blk_dev in blk_devices:
                    dom_dict['{#VIRSH_DOMAIN_DISK}'] = blk_dev

            dom_list.append(dom_dict)

        # Loop through the offline domains and retrieve the appropriate discovery information
        for name in conn.listDefinedDomains():
            dom_dict = {}
            vir_dom = conn.lookupByID(dom_id)
            dom_dict['{#VIRSH_DOMAIN_UUID}'] = vir_dom.UUIDString()

            if args.perfdata:
                dom_tree = ElementTree.fromstring(vir_dom.XMLDesc(0))

                #The list of device names
                if_devices = []

                #Iterate through all network interface target elements of the domain
                for target in dom_tree.findall("devices/interface/target"):
                    #Get the device name
                    dev = target.get("dev")

                    #If this device is already in the list, don't add it again
                    if not dev in if_devices:
                        if_devices.append(dev)

                #Put the final device list into the domain's return dict
                for if_num, if_dev in enumerate(if_devices):
                    dom_dict['{#VIRSH_DOMAIN_NIC}'] = str(if_num)

                #The list of device names
                blk_devices = []

                #Iterate through all network interface target elements of the domain
                for target in dom_tree.findall("devices/disk/target"):
                    #Get the device name
                    dev = target.get("dev")

                    #If this device is already in the list, don't add it again
                    if not dev in blk_devices:
                        blk_devices.append(dev)

                #Put the final device list into the domain's return dict
                for blk_dev in blk_devices:
                    dom_dict['{#VIRSH_DOMAIN_DISK}'] = blk_dev

            dom_list.append(dom_dict)

        return_dict['data'] = dom_list

        # return the data encoded as json
        print jsonpickle.encode(return_dict)

    except OSError:
        print 'Failed to get domain list'

def domain_list():
    try:
        # Connect to the local hypervisor (read only)
        conn = libvirt.openReadOnly(None)

        # Prepare the list of domains to return
        dom_list = []

        # Loop through the running domains, create and store the objects
        for id in conn.listDomainsID():
            vir_dom = conn.lookupByID(id)
            dom_obj = Domain(vir_dom)
            dom_list.append(dom_obj)

        # Loop through the offline domains, create and store the objects
        for name in conn.listDefinedDomains():
            vir_dom = conn.lookupByName(name)
            dom_obj = Domain(vir_dom)
            dom_list.append(dom_obj)

        return dom_list

    except OSError:
        print 'Failed to get domain list'
        return []


if __name__ == '__main__':
    args = parse_args()

    try:
        if args.version:
            print VERSION
        elif args.output == 'stdout':
            output_stdout(args)
        elif args.output == 'nagios':
            output_nagios(args)
        elif args.output == 'zabbix' and not args.discovery:
            output_zabbix(args)
        elif args.output == 'zabbix' and args.discovery:
            output_zabbix_discovery(args)
        sys.exit(0)
    except Exception, err:
        #print("ERROR: %s" % err)
        ex, val, tb = sys.exc_info()
        traceback.print_exception(ex, val, tb)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)