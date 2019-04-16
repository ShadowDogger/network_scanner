
import kamene.all as scapy

ip = input('Input target ip')


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=60, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
        # print(element[1].psrc + "\t\t" + element[1].hwsrc)
    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n_______________________________________\n")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


scan_result = scan(ip)

print_result(scan_result)
