import requests
import ast
import socket
import threading
import networkx as nx
import matplotlib.pyplot as plt
import sys
links_stats={}
flowDB = {}
arp_table = {}
hosts = []
serversock=''
controllerip = '199.165.75.160'

def tcpconnect(controllerip):
    global serversock
    global arp_table
    global hosts
    global flowDB
    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (controllerip, 8443)
    try:
        serversock.connect(server_address)
        print "connection with the application client established"
        data = serversock.recv(4096)
        if data:
            print "updating flow DB and arp_table"
            flowDB,arp_table = map(ast.literal_eval,data.split('%'))
            print "data",data
            for switch in arp_table:
                for host in arp_table[switch]:
                    hosts.append(host)

    except:
        print "connection to the application client failed exiting"
        serversock=''
        sys.exit(1)

def hostDiscovery():
    global serversock
    print serversock
    global flowDB
    global arptable
    while(1):
        try:
            data = serversock.recv(4096)
            
            if '%' in data:
                flowDB,arptable = map(ast.literal_eval,data.split('%'))
                print "updated flowdb and arptable"
                continue
            switch,host,port = data.split(',')
            print "Received Host ARP"
            print "--------------------------------------------------------"
            print data
            print "--------------------------------------------------------"
            if switch not in arp_table:
                arp_table[switch]={}

            if host not in arp_table[switch]:
                arp_table[switch][host]=port
                hosts.append(host)
                print "Updated HOST table "
                print "--------------------------------------------------------"
                print "host discovered ",hosts
                for switch,value in arp_table.iteritems():
                    print switch,value
                print "--------------------------------------------------------"
        except:
            pass
hostdiscoverythread = threading.Thread(target=hostDiscovery,args=())
hostdiscoverythread.start()



def topologyviewer():
    build_link_stats(controllerip)
    G = nx.Graph()
    
    for switch in links_stats:
        G.add_node(switch)
        for i in links_stats[switch]:
            G.add_edge(switch,i)
    for switch in arp_table:
        for i in arp_table[switch]:
            G.add_edge(switch,i)
    
 
    nx.draw(G,with_labels=True)
    plt.savefig("topology.png")
    plt.show()


def build_link_stats(controller_ip):
    links = requests.get('http://'+controller_ip+':8080/v1.0/topology/links')
    links = ast.literal_eval(links.text)
    for link in links:
        if link['src']['dpid'] not in links_stats:
            links_stats[link['src']['dpid']] = {}
            links_stats[link['src']['dpid']][link['dst']['dpid']] = link['src']['port_no']
        else:
            links_stats[link['src']['dpid']][link['dst']['dpid']] = link['src']['port_no']

    for key,value in links_stats.iteritems():
        print key,value

def get_flow(switchlist,dstip):
    flow=[]    
    global links_stats
    for switch in switchlist:
        if switch not in links_stats:
            return flow
    prev = links_stats[switchlist[0]]
    prev_switch = switchlist[0]
    
    for switch in switchlist[1:]:
        if switch in prev:
            flow.append((prev_switch,prev[switch]))
        prev = links_stats[switch]
        prev_switch=switch
    if dstip in arp_table[prev_switch]:
        flow.append((prev_switch,arp_table[prev_switch][dstip]))
    return flow

def build_flowDB(srcip,dstip,protocol,switches):
    global flowDB
    if srcip not in flowDB:
        flowDB[srcip] = {}
        flowDB[srcip][dstip] = {}
        flow = get_flow(switches,dstip)                                                                                                                                                                 
        if len(flow) == len(switches):
            flowDB[srcip][dstip][protocol] = flow
            print "flow for all the switches genrated and flow updated"
            return 1;
        else:
            print "improper list of switches for the srcip and dstip"
            return 0;

    else:
        if dstip not in flowDB[srcip]:
            flowDB[srcip][dstip]={}
            flow = get_flow(switches,dstip)
            if len(flow) == len(switches):
                flowDB[srcip][dstip][protocol] = flow
                print "flow for all the switches genrated and flow updated"
                return 1;
            else:
                print "improper list of switches for the srcip and dstip"
                return 0;
        else:
            flow = get_flow(switches,dstip)
            if len(flow) == len(switches):
                flowDB[srcip][dstip][protocol] = flow
                print "flow for all the switches genrated and flow updated"
                return 1;
            else:
                print "improper list of switches for the srcip and dstip"
                return 0;

    
def sendFlowtoController(controller_ip,srcip,dstip,portno,switches):
    global serversock

    build_link_stats(controller_ip)

    update_f = build_flowDB(srcip,dstip,portno,switches)
    switches.reverse()
    update_r = build_flowDB(dstip,srcip,portno,switches)
    switches.reverse()

    update_df = build_flowDB(srcip,dstip,"default",switches)
    switches.reverse()
    update_dr = build_flowDB(dstip,srcip,"default",switches)
    switches.reverse()
    
    if update_f and update_r and update_df and update_dr:
        print "Updated the Flow DB "
        print "-------------------------------------------------------------"
        print flowDB
        print "-------------------------------------------------------------"
        try:
            serversock.send(str(flowDB)+'%'+str(arp_table))
            print "Sent the updated flow DB"
        except:
            print "Failed to send the flowDB"
    else:
        print "flow construction failed because of the improper list of switches"

def deletearpflow(controllerip,dpid,dstip,out_port):

    r = requests.post('http://'+controllerip+':8080/stats/flowentry/delete',data='{"dpid": '+str('0x'+dpid[3:])+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x806,"nw_dst":"'+str(dstip)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}')
    print "removing flow"
    print 'http://'+controllerip+':8080/stats/flowentry/deletedata={"dpid": '+str('0x'+dpid[3:])+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x806,"nw_dst":"'+str(dstip)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}'
    if r.status_code == requests.codes.ok:
        print "successfully removed flow in the switch"
    else:
        print "failed removing flow"

def deletetcpdstflow(controllerip,dpid,dstip,tcpport,out_port):

    r = requests.post('http://'+controllerip+'8080/stats/flowentry/add',data='{"dpid": '+str('0x'+dpid[3:])+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(dstip)+'","ip_proto":6,"tcp_dst":"'+str(tcpport)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}')
    print "tcp flow mod for switch"
    print 'http://'+controllerip+':8080/stats/flowentry/add,data={"dpid": '+str('0x'+dpid[3:])+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(dstip)+'","ip_proto":6,"tcp_dst":"'+str(tcpport)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}'
    if r.status_code == requests.codes.ok:
        print "successfully removed tcp flow in the switch"
    else:
        print "failed removing flow "

def deletetcpsrcflow(controllerip,dpid,dstip,tcpport,out_port):

    r = requests.post('http://'+controllerip+':8080/stats/flowentry/add',data='{"dpid": '+str('0x'+dpid[3:])+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(dstip)+'","ip_proto":6,"tcp_src":"'+str(tcpport)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}')
    print "tcp flow mod for switch"
    print 'http://'+controllerip+':8080/stats/flowentry/add,data={"dpid": '+str('0x'+dpid[3:])+',"table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(dstip)+'","ip_proto":6,"tcp_src":"'+str(tcpport)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}'
    if r.status_code == requests.codes.ok:
        print "successfully removed tcp flow in the switch"
    else:
        print "failed removing flow "

def deleteflow(controllerip,srcip,dstip,switches,port):
    
    global flowDB
    global serversock

    if srcip in flowDB:
        if dstip in flowDB[srcip]:
            for protocols in flowDB[srcip][dstip]:
                print "sending delete flow request to the controller"
                if protocols == port:
                    for switch in flowDB[srcip][dstip][protocols]:
                        deletetcpdstflow(controllerip,switch[0],dstip,switch[1],port)
            print "Emptying up the Flow DB for srcip %s dstip %s and sending to the controller" %(srcip,dstip)
            flowDB[srcip][dstip]={}
            try:
                serversock.send(str(flowDB))
                print "Sent the updated flow DB"
            except:
                print "Failed to send the flowDB"
                        

    switches.reverse()
    if dstip in flowDB:
        if srcip in flowDB[dstip]:
            for protocols in flowDB[dstip][srcip]:
                if protocols == port:
                    for switch in flowDB[dstip][srcip][port]:
                        deletetcpsrcflow(controllerip,switch[0],srcip,switch[1],port)

            
        print "Emptying up the Flow DB for dstip %s srcip %s and sending to the controller" %(dstip,srcip)
        flowDB[dstip][srcip]={}
        try:
            serversock.send(str(flowDB))
            print "Sent the updated flow DB"
        except:
            print "Failed to send the flowDB"
    switches.reverse()                        


def main():
    tcpconnect(controllerip)
    global serversock
    print "Enter (1) for insert flows, (2) for view flowDB, (3) delete flows, (4) view topology, (c) to exit"
    userinput = raw_input()
    while (userinput != 'c'):
        if userinput == '1':
            srcip = raw_input("source ip address:")
            dstip = raw_input("destination ip address:")
            portno = raw_input("Port no:")
            switches = raw_input("list of comma seperated switches").split(',')
            sendFlowtoController(controllerip,srcip,dstip,portno,switches)
        elif userinput == '2':
            print "flow DataBase"
            print "--------------------------------------------------------------"
            print flowDB
            print "--------------------------------------------------------------"
        elif userinput == '3':
            srcip = raw_input("source ip address:")
            dstip = raw_input("destination ip address:")
            portno = raw_input("Port no:")
            switches = raw_input("list of comma seperated switches").split(',')
            deleteflow(controllerip,srcip,dstip,switches,portno)
        elif userinput == '4':
            topologyviewer()
        elif userinput == '5':
            print "send random"
            serversock.send("random")
        print "Enter (1) for insert flows, (2) for view flowDB, (3) delete flows, (4) view topology, (c) to exit"
        userinput = raw_input()
    serversock.send('Kill thread')
    hostdiscoverythread._Thread__stop()         
if __name__ == '__main__':
    main()


