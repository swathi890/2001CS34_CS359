from scapy.all import *

# Create SYN packet
ip = IP(src="172.16.189.155", dst="35.190.43.130")
syn = TCP(sport=1234, dport=80, flags="S", seq=1000)
pkt = ip/syn

# Send SYN packet and receive SYN-ACK response
syn_ack = sr1(pkt)

# Create ACK packet
ack = TCP(sport=1234, dport=80, flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
pkt = ip/ack

# Send ACK packet and receive response
response = sr1(pkt)

# Create FIN packet
fin = TCP(sport=1234, dport=80, flags="FA", seq=response.ack, ack=response.seq + 1)
pkt = ip/fin

# Send FIN packet and receive FIN-ACK response
fin_ack = sr1(pkt)

# Create ACK packet to complete connection termination
ack = TCP(sport=1234, dport=80, flags="A", seq=fin_ack.ack, ack=fin_ack.seq + 1)
pkt = ip/ack

# Send ACK packet to complete connection termination
send(pkt)

# Save the captured packets as a pcap file
wrpcap("tcp_handshake.pcap", [syn, syn_ack, ack, response, fin, fin_ack, ack])

