import re
from collections import defaultdict

import pyshark


class Filtters:

    def __init__(self, pcap_path):
        self.pcap_path = pcap_path

    def protocol_detector(self, cap):
        if ("tcp" in cap):
            return 'tcp'
        elif ('udp' in cap):
            return 'udp'
        elif ('icmp' in cap):
            return 'icmp'

    def get_service(self, cap):
        proto = self.protocol_detector(cap)
        private_regx = re.compile('(192)\.(168)(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){2}')
        if (proto == 'tcp'):
            highest_layer = cap.highest_layer
            port = cap.tcp.dstport
            ip_src = cap.ip.addr
            ip_dst = cap.ip.dst

            if (private_regx.match(ip_src) and private_regx.match(ip_dst)):
                return 'private'
            elif (port == self.services.tcp.auth):
                return 'auth'
            elif (port == self.services.tcp.csnet_ns):
                return 'csnet_ns'
            elif (port == self.services.tcp.ctf):
                return 'ctf'
            elif (port == self.services.tcp.discard):
                return 'discard'
            elif (port == self.services.tcp.domain):
                return 'domain'
            elif (port == self.services.tcp.harvest):
                return 'harvest'
            elif (port == self.services.tcp.http_2784):
                return 'http_2784'
            elif (port == self.services.tcp.http_8001):
                return 'http_8001'
            elif (port == self.services.tcp.http_443):
                return 'http_443'
            elif (port == self.services.tcp.iso_tsap):
                return 'iso_tsap'
            elif (port == self.services.tcp.netbios_dgm):
                return 'netbios_dgm'
            elif (port == self.services.tcp.netbios_ns):
                return 'netbios_ns'
            elif (port == self.services.tcp.netbios_ssn):
                return 'netbios_ssn'
            elif (port == self.services.tcp.nnsp):
                return 'nnsp'
            elif (port == self.services.tcp.nntp):
                return 'nntp'
            elif (port == self.services.tcp.pop_2):
                return 'pop_2'
            elif (port == self.services.tcp.printer):
                return 'printer'
            elif (port == self.services.tcp.shell):
                return 'shell'
            elif (port == self.services.tcp.sql_net):
                return 'sql_net'
            elif (port == self.services.tcp.sunrpc):
                return 'sunrpc'
            elif (port == self.services.tcp.supdup):
                return 'supdup'
            elif (port == self.services.tcp.systat):
                return 'systat'
            elif (port == self.services.tcp.uucp):
                return 'uucp'
            elif (port == self.services.tcp.uucp_path):
                return 'uucp_path'
            elif (highest_layer == self.services.tcp.aol.upper() or
                  highest_layer == self.services.tcp.aol):
                return 'aol'
            elif (highest_layer == self.services.tcp.bgp.upper() or
                  highest_layer == self.services.tcp.bgp):
                return 'bgp'
            elif (highest_layer == self.services.tcp.daytime.upper() or
                  highest_layer == self.services.tcp.daytime):
                return 'daytime'
            elif (highest_layer == self.services.tcp.echo.upper() or
                  highest_layer == self.services.tcp.echo):
                return 'echo'
            elif (highest_layer == self.services.tcp.efs.upper() or
                  highest_layer == self.services.tcp.efs):
                return 'efs'
            elif (highest_layer == self.services.tcp.exec.upper() or
                  highest_layer == self.services.tcp.exec):
                return 'exec'
            elif (highest_layer == self.services.tcp.finger.upper() or
                  highest_layer == self.services.tcp.finger):
                return 'finger'
            elif (highest_layer == self.services.tcp.ftp.upper() or
                  highest_layer == self.services.tcp.ftp):
                return 'ftp'
            elif (highest_layer == self.services.tcp.ftp_dta.upper() or
                  highest_layer == self.services.tcp.ftp_dta):
                return 'ftp_dta'
            elif (highest_layer == self.services.tcp.gopher.upper() or
                  highest_layer == self.services.tcp.gopher):
                return 'gopher'
            elif (highest_layer == self.services.tcp.http.upper() or
                  highest_layer == self.services.tcp.http):
                return 'http'
            elif (highest_layer == self.services.tcp.IRC.upper() or
                  highest_layer == self.services.tcp.IRC):
                return 'IRC'
            elif (highest_layer == self.services.tcp.ldap.upper() or
                  highest_layer == self.services.tcp.ldap):
                return 'ldap'
            elif (highest_layer == self.services.tcp.ldap.upper() or
                  highest_layer == self.services.tcp.ldap):
                return 'ldap'
            elif (highest_layer == self.services.tcp.link.upper() or
                  highest_layer == self.services.tcp.link):
                return 'link'
            elif (highest_layer == self.services.tcp.netbios.upper() or
                  highest_layer == self.services.tcp.netbios):
                return 'netbios'
            elif (highest_layer == self.services.tcp.pop_3.upper() or
                  highest_layer == self.services.tcp.pop_3):
                return 'pop_3'
            elif (highest_layer == self.services.tcp.smtp.upper() or
                  highest_layer == self.services.tcp.smtp):
                return 'smtp'
            elif (highest_layer == self.services.tcp.ssh.upper() or
                  highest_layer == self.services.tcp.ssh):
                return 'ssh'
            elif (highest_layer == self.services.tcp.telnet.upper() or
                  highest_layer == self.services.tcp.telnet):
                return 'telnet'
            elif (highest_layer == self.services.tcp.time.upper() or
                  highest_layer == self.services.tcp.time):
                return 'time'
            elif (highest_layer == self.services.tcp.vmnet.upper() or
                  highest_layer == self.services.tcp.vmnet):
                return 'vmnet'
            elif (highest_layer == self.services.tcp.whois.upper() or
                  highest_layer == self.services.tcp.whois):
                return 'whois'
            elif (highest_layer == self.services.tcp.x11.upper() or
                  highest_layer == self.services.tcp.x11):
                return 'x11'
            elif (highest_layer == self.services.tcp.Z39_50.upper() or
                  highest_layer == self.services.tcp.Z39_50):
                return 'Z39_50'
            else:
                return 'other'

        elif (proto == 'udp'):
            highest_layer = cap.highest_layer
            port = cap.udp.dstport
            ip_src = cap.ip.addr
            ip_dst = cap.ip.dst

            if (private_regx.match(ip_src) and private_regx.match(ip_dst)):
                return 'private'
            elif (port == self.services.udp.domain_u):
                return 'domain_u'
            elif (highest_layer == self.services.udp.ntp_u.upper() or
                  highest_layer == self.services.udp.ntp_u):
                return 'ntp_u'
            elif (highest_layer == self.services.udp.tftp_u.upper() or
                  highest_layer == self.services.udp.tftp_u):
                return 'tftp_u'
            else:
                return 'other'

        else:
            code = cap.icmp.code
            type = cap.icmp.type
            ip_src = cap.ip.addr
            ip_dst = cap.ip.dst

            if (code == self.services.icmp.eco_i):
                return 'eco_i'
            elif (code == self.services.icmp.ecr_i):
                return 'ecr_i'
            elif (type == self.services.icmp.red_i):
                return 'red_i'
            else:
                return 'other'

    def get_flag(self, cap):
        proto = self.protocol_detector(cap)
        private_regx = re.compile('(192)\.(168)(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){2}')

        if (proto == 'tcp'):
            flags = cap.tcp.flags

            try:
                time_relative = cap.tcp.time_relative  # 0.0000032
            except:
                time_relative = '0.00'

            try:
                initial_rtt = cap.tcp.analysis_initial_rtt  # 0.010000
            except:
                initial_rtt = '0.00'

            try:
                nextseq = cap.tcp.nextseq
            except:
                nextseq = '0'

            ack = cap.tcp.flags_ack
            syn = cap.tcp.flags_syn
            reset = cap.tcp.flags_reset
            fin = cap.tcp.flags_fin
            ip_src = cap.ip.addr
            ip_dst = cap.ip.dst

            if (syn == '1' and ack == '0'):
                return 'SF'
            elif (syn == '0' and ack == '0'):
                return 'OTH'
            elif (reset == '1' and private_regx.match(ip_src)):
                return 'RSTO'
            elif (reset == '1' and private_regx.match(ip_dst)):
                return 'RSTR'
            elif (flags == '0x0012' and float(initial_rtt) > float(0)):
                return 'SH'
            elif ((syn == '1' and ack == '0') and (fin == '1' or reset == '1') and private_regx.match(ip_dst)):
                return 'S3'
            elif ((syn == '1' and ack == '0') and (fin == '1' or reset == '1') and private_regx.match(ip_src)):
                return 'S2'
            elif (syn == '1' and ack == '0' and nextseq != '1'):
                return 'S1'
            elif (flags == '0x0002' and float(time_relative) > float(0)):
                return 'S0'
            elif (reset == '1' and private_regx.match(ip_src) and
                  flags == '0x0002' and float(time_relative) > float(0)):
                return 'RSTOS0'
            else:
                return 'REJ'

        elif (proto == 'udp'):
            return 'SF'

        else:
            return 'SF'

    def get_land(self, cap):
        proto = self.protocol_detector(cap)

        if (proto == 'tcp'):
            port_dst = cap.tcp.dstport
            port_src = cap.tcp.srcport
            if (port_src == port_dst):
                return 1
            else:
                return 0
        elif (proto == 'udp'):
            port_dst = cap.udp.dstport
            port_src = cap.udp.srcport
            if (port_src == port_dst):
                return 1
            else:
                return 0
        else:
            return 0

    def get_urgent(self, cap):
        proto = self.protocol_detector(cap)
        if (proto == 'tcp'):
            urg = cap.tcp.flags_urg
            if (urg == '1'):
                return 1
            else:
                return 0
        else:
            return 0

    def get_logged_in(self, cap):
        proto = self.protocol_detector(cap)
        if (proto == 'tcp'):
            port = cap.tcp.dstport
            if (port == self.services.tcp.shell):
                if (cap['rsh'].command != '0' or cap['rsh'].command != ''):
                    return 1
                else:
                    return 0
            else:
                return 0
        else:
            return 0

    def is_host_login(self, cap):
        proto = self.protocol_detector(cap)
        if (proto == 'tcp'):
            port = cap.tcp.dstport
            if (port == self.services.tcp.shell):
                if (cap['rsh'].client_username == 'administrator' or cap['rsh'].client_username == 'root'):
                    return 1
                else:
                    return 0
            else:
                return 0
        else:
            return 0

    def is_guest_login(self, cap):
        proto = self.protocol_detector(cap)
        if (proto == 'tcp'):
            port = cap.tcp.dstport
            if (port == self.services.tcp.shell):
                if (cap['rsh'].client_username == 'anonymous' or cap['rsh'].client_username == 'guest'):
                    return 1
                else:
                    return 0
            else:
                return 0
        else:
            return 0

    def feature_extractor(self):
        cap = pyshark.FileCapture(self.pcap_path, display_filter="not arp")
        connection_holder = 0
        connection_index = 0
        connections = defaultdict(dict)
        duration = 0.00
        src_bytes = 0
        dst_bytes = 0
        f_ip_src = ''
        f_ip_dst = ''
        urg_number = 0
        lenth = len(list(cap))
        for i in range(lenth):
            if (i != lenth - 1):
                ipis = cap[i].ip.src
                ipid = cap[i].ip.dst
                ipins = cap[i + 1].ip.src
                ipind = cap[i + 1].ip.dst
                hi = cap[i].highest_layer
                hin = cap[i + 1].highest_layer
                if (((((ipis == ipind) and (ipid == ipins)) or ((ipis == ipins) and (ipid == ipind))) and (hi == hin))):
                    if (connection_index == 0):
                        connections['connection ' + str(connection_holder)] = {}
                        connections['connection ' + str(connection_holder)]['packets'] = []
                        f_ip_src = cap[i].ip.src
                        f_ip_dst = cap[i].ip.dst

                    connections['connection ' + str(connection_holder)]['packets'].append({})
                    connections['connection ' + str(connection_holder)]['packets'][connection_index]['m_PKT'] = cap[i]
                    if (f_ip_src == ipind and f_ip_dst == ipins):
                        src_bytes += int(cap[i].frame_info.len)
                    else:
                        dst_bytes += int(cap[i].frame_info.len)

                    urg_number += self.get_urgent(cap[i])
                    connection_index += 1
                else:
                    INDEX = 'connection ' + str(connection_holder)
                    if ('packets' in connections[INDEX]):
                        connections[INDEX]['features'] = {}
                        duration = float(cap[i].frame_info.time_relative) - duration
                        connections[INDEX]['features']["duration"] = int(duration)
                        connections[INDEX]['features']["protocol"] = self.protocol_detector(cap[i])

                        if (connections[INDEX]['features']["protocol"] == 'icmp'):

                            connections[INDEX]['features']['data_len'] = int(cap[i].icmp.data_len)

                        connections[INDEX]['features']["service"] = self.get_service(cap[i])
                        connections[INDEX]['features']["flag"] = self.get_flag(cap[i])
                        if (f_ip_src == cap[i].ip.src):
                            src_bytes += int(cap[i].frame_info.len)
                        else:
                            dst_bytes += int(cap[i].frame_info.len)

                        connections[INDEX]['features']["src_bytes"] = src_bytes
                        connections[INDEX]['features']["dst_bytes"] = dst_bytes
                        src_bytes = 0
                        dst_bytes = 0
                        f_ip_src = ''
                        f_ip_dst = ''

                        connections[INDEX]['features']["land"] = self.get_land(cap[i])
                        connections[INDEX]['features']["urgent"] = urg_number
                        connections[INDEX]['features']["logged_in"] = self.get_logged_in(cap[i])
                        connections[INDEX]['features']["is_host_login"] = self.is_host_login(cap[i])
                        connections[INDEX]['features']["is_guest_login"] = self.is_guest_login(cap[i])

                        connection_holder += 1
                        connection_index = 0
            else:
                INDEX = 'connection ' + str(connection_holder)
                if ('packets' in connections[INDEX]):
                    INDEX = 'connection ' + str(connection_holder)
                    connections[INDEX]['features'] = {}
                    duration = float(cap[i].frame_info.time_relative) - duration
                    connections[INDEX]['features']["duration"] = int(duration)
                    connections[INDEX]['features']["protocol"] = self.protocol_detector(cap[i])

                    if (connections[INDEX]['features']["protocol"] == 'icmp'):

                        connections[INDEX]['features']['data_len'] = int(cap[i].icmp.data_len)

                    connections[INDEX]['features']["service"] = self.get_service(cap[i])
                    connections[INDEX]['features']["flag"] = self.get_flag(cap[i])
                    if (f_ip_src == cap[i].ip.src):
                        src_bytes += int(cap[i].frame_info.len)
                    else:
                        dst_bytes += int(cap[i].frame_info.len)

                    connections[INDEX]['features']["src_bytes"] = src_bytes
                    connections[INDEX]['features']["dst_bytes"] = dst_bytes
                    src_bytes = 0
                    dst_bytes = 0
                    f_ip_src = ''
                    f_ip_dst = ''

                    connections[INDEX]['features']["land"] = self.get_land(cap[i])
                    connections[INDEX]['features']["urgent"] = urg_number
                    connections[INDEX]['features']["logged_in"] = self.get_logged_in(cap[i])
                    connections[INDEX]['features']["is_host_login"] = self.is_host_login(cap[i])
                    connections[INDEX]['features']["is_guest_login"] = self.is_guest_login(cap[i])

                    connection_holder += 1
                    connection_index = 0

        return connections

    class services:

        class udp:
            domain_u = "139"
            ntp_u = "ntp"
            tftp_u = "tftp"

        class tcp:
            aol = "aol"
            auth = "464"
            bgp = "bgp"
            csnet_ns = "105"
            ctf = "84"
            daytime = "daytime"
            discard = "9"
            domain = "139"
            echo = "echo"
            efs = "efs"
            exec = "exec"
            finger = "finger"
            ftp = "ftp"
            ftp_dta = "ftp_dta"
            gopher = "gopher"
            harvest = "49152"
            http = "http"
            http_2784 = "2784"
            http_443 = "443"
            http_8001 = "8001"
            IRC = "irc"
            iso_tsap = "102"
            ldap = "ldap"
            link = "link16"
            netbios = "netbios"
            netbios_dgm = "138"
            netbios_ns = "137"
            netbios_ssn = "139"
            nnsp = "433"
            nntp = "119"
            pop_2 = "109"
            pop_3 = "pop"
            printer = "6001"
            shell = "514"
            smtp = "smtp"
            sql_net = "1521"
            ssh = "ssh"
            sunrpc = "111"
            supdup = "95"
            systat = "11"
            telnet = "telnet"
            time = "time"
            uucp = "540"
            uucp_path = "117"
            vmnet = "vmlab"
            whois = "whois"
            x11 = "x11"
            Z39_50 = "z3950"

        class icmp:
            # by type
            eco_i = "0"
            ecr_i = "8"
            # bycode
            red_i = "1"
