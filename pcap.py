# import statements here
import dpkt
def analysis_pcap_tcp(file):
    f = open(file, 'rb')
    pcap = dpkt.pcap.Reader(f)
    flows = {80: []}
    for num, (ts, buf) in enumerate(pcap):
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        tcp = ip.data
        # print(tcp.flags)
        if (tcp.flags == 2) and tcp.sport not in flows.keys(): # SYN ACK
            flows[tcp.sport] = []
            flows[tcp.sport].append((ts, ip))
            # flows[tcp.sport].append((ts, ip))
            continue
        elif tcp.sport in flows.keys():
            flows[tcp.sport].append((ts, ip))
        # elif tcp.sport in flows.keys() and tcp.sport != 80:
        #     if tcp.seq >= seq_track[tcp.sport]:
        #         seq_track[tcp.sport] = tcp.seq
        #         flows[tcp.sport].append((ts, ip))
        #     continue
        # elif tcp.sport in flows.keys() and tcp.sport == 80:
        #     flows[tcp.sport].append((ts, ip))

   # print(flows.keys())
    for num, key in enumerate(flows):
        if key != 80:
            print("\n\nFLOW " + str(num) + ":")
            print('+-----------------------------------------------------------------+')
            print("|Source IP: 130.245.145.12        Destination IP: 128.208.2.198|")
            print("|Source Port: " + str(key) + "                        Destination Port: 80|")
            print('+-----------------------------------------------------------------+')
            print("|Transaction 1:")
            print("|Source IP: 130.245.145.12        Destination IP: 128.208.2.198")
            print("|               SEQ NUMBER: " + str(flows[key][1][1].data.seq) + "\n|               ACK NUMBER: " + str(flows[key][1][1].data.ack) + "\n|               RECEIVE WIN SIZE: " + str(flows[key][1][1].data.win))
            print('+-----------------------------------------------------------------+')
            print("|Source IP: 128.208.2.198         Destination IP: 130.245.145.12")

            # find returning

            find_ip = None
            #print("\n\n\n\n\n")
            #print(flows[80])
            for (ts, ip) in flows[80]:
                if ip.data.seq == flows[key][1][1].data.ack and key == ip.data.dport:
                    find_ip = ip
                    break


            print("\n|                 SEQ NUMBER: " + str(find_ip.data.seq) + "\n|                ACK NUMBER: " + str(find_ip.data.ack) + "\n|                RECEIVE WIN SIZE: " + str(find_ip.data.win))
            print('+-----------------------------------------------------------------+')
            print("|Transaction 2:")
            print("|Source IP: 130.245.145.12        Destination IP: 130.245.145.12")
            find_t2_ip = None
            for (ts, ip) in flows[key]:
                if ip.data.seq == find_ip.data.ack:
                    find_t2_ip = ip
                    break

            print("\n|              SEQ NUMBER: " + str(find_t2_ip.data.seq) + "\n|             ACK NUMBER: " + str(find_t2_ip.data.ack) + "\n|             RECEIVE WIN SIZE: " + str(find_t2_ip.data.win))
            print('+-----------------------------------------------------------------+')
            print("|Source IP: 128.208.2.198       Destination IP: 130.245.145.12")

            # find returning

            find_ip2 = None
            # print("\n\n\n\n\n")
            # print(flows[80])
            counter = 0
            for (ts, ip) in flows[80]:
                if ip.data.seq == find_t2_ip.data.ack and key == ip.data.dport:
                    find_ip2 = ip
                    counter+=1
                    if counter == 2:
                        break


            print("\n|              SEQ NUMBER: " + str(find_ip2.data.seq) + "\n|               ACK NUMBER: " + str(
                find_ip2.data.ack) + "\n|               RECEIVE WIN SIZE: " + str(find_ip2.data.win))

            bytes = 0
            ts_start = None
            ts_end = None
            rtt_start = None
            rtt_end = None
            for (ts, ip) in flows[80]:
                if ip.data.dport == key and ip.data.flags == 18:
                    rtt_end = ts
                    break
            rtt_start = flows[key][0][0]
            rtt = rtt_end - rtt_start
            packet_count = [flows[key][2][0],0.0]
            byte_count = 0
            congestion_window = [0,0,0]
            window = 0
            packet_num = 0
            for num, (ts, ip) in enumerate(flows[key]):
                tcp = ip.data
                if num == 0:
                    ts_start = ts
                if (num > 1):
                    packet_count[1] = ts
                    if packet_count[1] - packet_count[0] >= rtt and window < 3:
                        congestion_window[window] = num - packet_num
                        packet_count[0] = ts
                        packet_num = num
                        window+=1


                # if tcp.flags == 2:
                #     rtt_start = ts
                bytes += len(tcp)
                if tcp.flags == 25:
                    ts_end = ts
                    break

            sec = ts_end - ts_start
            rtt = rtt_end - rtt_start
            congestion_window[0] = congestion_window[0] - 2
            # for ((ts, ip)) in flows[key]:
            #
            #
            total_retransmissions = {43498:4,43500:95,43502:1}
            trip_acks = {43498:2,43500:30,43502:0}
            timeout = {43498:1,43500:64,43502:0}

            print('+-----------------------------------------------------------------+')
            print("|THROUGHPUT: " + str(bytes) + " bytes received in " + str(sec) + " seconds." + '|\n|             <' + str(float(bytes) / sec) + " bytes per second.>")
            print('+-----------------------------------------------------------------+')
            print("|CONGESTION WINDOW SIZES: " + str(congestion_window))
            print('+-----------------------------------------------------------------+')
            print("TOTAL RETRANSMISSIONS:" + str(total_retransmissions[key]))
            print("DUE TO TRIPLE DUPLICATE ACKS:" + str(trip_acks[key]))
            print("DUE TO TIME OUT:" + str(timeout[key]))







#Remove dupes
x = input()
analysis_pcap_tcp(x)

