# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet

from ryu.lib.packet import ethernet,arp,ipv4,tcp
from ryu.lib.packet import ether_types
import socket
import ast
import threading
import requests

class flowClassifier(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(flowClassifier, self).__init__(*args, **kwargs)
        self.flowDB = {}
        self.arptable={}
        self.connection=''
        TCPthread = threading.Thread(target=self.ListentoApp,args=())
        TCPthread.start()
        
    def ListentoApp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('0.0.0.0', 8443)
        sock.bind(server_address)
        sock.listen(1)
        while(1):
            self.connection, client_address = sock.accept()
            print "Connection received from Application"
            self.connection.send(str(self.flowDB)+'%'+str(self.arptable))   
            while(1):
                try:
                    data = self.connection.recv(4096)
                    if data == 'Kill thread':
                        print "closing connection with Application"
                        self.connection.close()
                        self.connection=''
                        break;
                    
                    if '%' in data:
                        self.flowDB,self.arptable = map(ast.literal_eval,data.split('%'))
                        print "updated flowDB"
                        print "--------------------------------------------------------"
                        print self.flowDB
                        print "--------------------------------------------------------"

                        print "updated arptable"
                        print "--------------------------------------------------------"
                        print self.arptable
                        print "--------------------------------------------------------" 
                    elif data:
                        print "updated flowDB"
                        print "--------------------------------------------------------"
                        self.flowDB = ast.literal_eval(data)
                        print self.flowDB
                        print "--------------------------------------------------------"
                except:
                    continue


    def get_arp_outport(self,s,dstip,srcip):

        print "got a arp packet for switch %s, srcip %s, dstip %s"%(s,srcip,dstip)
        port = ''
        if str(srcip) in self.flowDB:

            if str(dstip) in self.flowDB[srcip]:
                i=False
                for switches in self.flowDB[srcip][dstip]["default"]:
                    if i:
                        switch = switches[0]
                        hexdpid = '0x'+switch[4:]
                        out_port = switches[1]
                        r = requests.post('http://localhost:8080/stats/flowentry/add',data='{"dpid": '+str(hexdpid)+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0806,"nw_dst":"'+str(dstip)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}')
                        print "installing arp flow for other switch ",switch
                        print 'http://localhost:8080/stats/flowentry/add,data={"dpid": '+switch+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0806,"nw_dst":"'+str(dstip)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}'
                        if r.status_code == requests.codes.ok:
                            print "successfully installed arp flow in the switch"
                        else:
                            print "failed installing arp flow mod"
                    i = True;    
                    if s == switches[0]:
                        port = switches[1]
        return port

    def get_icmp_outport(self,s,dstip,srcip):

        print "got a icmp packet for switch %s, srcip %s, dstip %s"%(s,srcip,dstip)
        port = ''
        if str(srcip) in self.flowDB:

            if str(dstip) in self.flowDB[srcip]:
                i=False
                for switches in self.flowDB[srcip][dstip]["default"]:
                    if i:
                        switch = switches[0]
                        hexdpid = '0x'+switch[4:]
                        out_port = switches[1]
                        r = requests.post('http://localhost:8080/stats/flowentry/add',data='{"dpid": '+str(hexdpid)+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0806,"nw_dst":"'+str(dstip)+'","ip_proto":1},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}')
                        print "installing icmp flow for other switch ",switch
                        print 'http://localhost:8080/stats/flowentry/add,data={"dpid": '+switch+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0806,"nw_dst":"'+str(dstip)+'","ip_proto":1},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}'
                        if r.status_code == requests.codes.ok:
                            print "successfully installed icmp flow in the switch"
                        else:
                            print "failed installing icmp flow mod"
                    i = True;    
                    if s == switches[0]:
                        port = switches[1]
        return port
    def get_tcp_outport(self,s,dstip,srcip,dstport,srcport):

        print "got a tcp packet installing for switch %s, srcip %s, dstip %s"%(s,srcip,dstip)
        print dstport,srcport
        oport=''
        tcpport=''
        sd=''
        print self.flowDB
        if str(srcip) in self.flowDB:

            if str(dstip) in self.flowDB[srcip]:

                if str(dstport) in self.flowDB[srcip][dstip]:
                    i=False
                    for switches in self.flowDB[srcip][dstip][str(dstport)]:
                        if i:
                            switch = switches[0]
                            hexdpid = '0x'+switch[4:]
                            out_port = switches[1]
                            r = requests.post('http://localhost:8080/stats/flowentry/add',data='{"dpid": '+str(hexdpid)+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 2,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(ipv4_pkt.dst)+'","ip_proto":6,"tcp_dst":"'+str(dstport)+'"},"actions":[]}')
                            if r.status_code == requests.codes.ok:
                                print "successfully installed tcp flow in the switch"
                            else:
                                print "failed installing flow mod"
                            print "tcp flow mod for switch"
                            print 'http://localhost:8080/stats/flowentry/add,data={"dpid": '+switch+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(ipv4_pkt.dst)+'","ip_proto":6,"tcp_dst":"'+str(dstport)+'"},"actions":[]}'
                        i = True;    
                        if s == switches[0]:
                            oport = switches[1]
                            tcpport = str(dstport)
                            sd = 'dst'
                



                if str(srcport) in self.flowDB[srcip][dstip]:
                    i=False
                    for switches in self.flowDB[srcip][dstip][str(srcport)]:
                        if i:
                            switch = switches[0]
                            hexdpid = '0x'+switch[4:]
                            out_port = switches[1]
                            r = requests.post('http://localhost:8080/stats/flowentry/add',data='{"dpid": '+str(hexdpid)+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 2,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(ipv4_pkt.dst)+'","ip_proto":6,"tcp_src":"'+str(srcport)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}')
                            if r.status_code == requests.codes.ok:
                                print "successfully installed tcp flow in the switch"
                            else:
                                print "failed installing flow mod"
                            print "tcp flow mod for switch"
                            print 'http://localhost:8080/stats/flowentry/add,data={"dpid": '+switch+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(ipv4_pkt.dst)+'","ip_proto":6,"tcp_src":"'+str(srcport)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}'
                        i = True;    
                        if s == switches[0]:
                            oport = switches[1]
                            tcpport = str(dstport)
                            sd = 'dst'
                

        return oport,tcpport,sd



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)

    def _packet_in_handler(self, ev):

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet

            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        dst = eth.dst
        src = eth.src
        hexdpid = datapath.id
        dpid = '0000'+hex(datapath.id)[2:]
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if arp_pkt:
            if arp_pkt.dst_ip not in self.flowDB:
                print "Received arp packet "
                print dpid,arp_pkt.src_ip,in_port
            if self.connection:
                self.connection.send(str(dpid)+','+str(arp_pkt.src_ip)+','+str(in_port))
                print "sending host discovery to Application" 
            else:
                print "Application not connected"  
            out_port  = self.get_arp_outport(dpid,arp_pkt.dst_ip,arp_pkt.src_ip)
            if not out_port:
                print "could not find output port to forward arp packet"
                return
            print "forwarding the arp packet out of output port ",out_port

            actions = [parser.OFPActionOutput(int(out_port))]
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

            r = requests.post('http://localhost:8080/stats/flowentry/add',data='{"dpid": '+str(hexdpid)+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0806,"nw_dst":"'+str(arp_pkt.dst_ip)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}')
            print "installing arp flow for switch"
            print 'http://localhost:8080/stats/flowentry/add,data={"dpid": '+dpid+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0806,"nw_dst":"'+str(arp_pkt.dst_ip)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}'
            if r.status_code == requests.codes.ok:
                print "successfully installed arp flow in the switch"
            else:
                print "failed installing arp flow mod"

        elif tcp_pkt:
            print "tcp"
            out_port,tcpport,sd  = self.get_tcp_outport(dpid,ipv4_pkt.dst,ipv4_pkt.src,tcp_pkt.dst_port,tcp_pkt.src_port)
            if not out_port:
                print "could not find output port to forward for the tcp packet"
                print "sending flow to install to drop the packet"
                r = requests.post('http://localhost:8080/stats/flowentry/add',data='{"dpid": '+str(hexdpid)+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 2,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(ipv4_pkt.dst)+'","ip_proto":6,"tcp_'+sd+'":"'+str(tcpport)+'"},"actions":[]}')
                if r.status_code == requests.codes.ok:
                    print "successfully installed tcp flow in the switch"
                else:
                    print "failed installing flow mod"
                print "tcp flow mod for switch"
                print 'http://localhost:8080/stats/flowentry/add,data={"dpid": '+dpid+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(ipv4_pkt.dst)+'","ip_proto":6,"tcp_'+sd+'":"'+str(tcpport)+'"},"actions":[]}'
                return
            

            actions = [parser.OFPActionOutput(int(out_port))]
            data = None

            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        
            r = requests.post('http://localhost:8080/stats/flowentry/add',data='{"dpid": '+str(hexdpid)+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(ipv4_pkt.dst)+'","ip_proto":6,"tcp_'+sd+'":"'+str(tcpport)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}')
            print "tcp flow mod for switch"
            print 'http://localhost:8080/stats/flowentry/add,data={"dpid": '+dpid+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(ipv4_pkt.dst)+'","ip_proto":6,"tcp_'+sd+'":"'+str(tcpport)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}'
	    



            if r.status_code == requests.codes.ok:
                print "successfully installed tcp flow in the switch"
            else:
                print "failed installing flow mod"

        elif ipv4_pkt:
            print "ipv4 packet"
            if not ipv4_pkt.proto == 1:
                return
            print "icmp packet recieved"
            out_port  = self.get_icmp_outport(dpid,ipv4_pkt.dst,ipv4_pkt.src)

            if not out_port:
                print "could not find output port to forward for the IP packet"
                return

            actions = [parser.OFPActionOutput(int(out_port))]
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

            r = requests.post('http://localhost:8080/stats/flowentry/add',data='{"dpid": '+str(hexdpid)+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x800,"nw_dst":"'+str(ipv4_pkt.dst)+'","ip_proto":1},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}')
            print "installing flow mod for ip packet"
            print 'http://localhost:8080/stats/flowentry/add,data={"dpid": '+dpid+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x800,"nw_dst":"'+str(ipv4_pkt.dst)+'","ip_proto":1},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}'
            if r.status_code == requests.codes.ok:
                print "successfully installed ip flow in the switch"
            else:
                print "failed installing flow mod"
app_manager.require_app('ryu.app.rest_topology')
app_manager.require_app('ryu.app.ofctl_rest')


