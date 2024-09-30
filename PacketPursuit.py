from scapy.all import *
import argparse
import time
import sys

def traceroute_host(host, max_ttl=30, timeout=2, use_tcp=False, port=80):
    result = []
    print(f"\nTracerouting to {host} with max TTL {max_ttl} and timeout {timeout}s")
    for ttl in range(1, max_ttl + 1):
        if use_tcp:
            pkt = IP(dst=host, ttl=ttl) / TCP(dport=port, flags='S')
        else:
            pkt = IP(dst=host, ttl=ttl) / ICMP()
        
        send_time = time.time()
        reply = sr1(pkt, verbose=0, timeout=timeout)
        rtt = (time.time() - send_time) * 1000 
        
        if reply is None:
            print(f"{ttl:<3} *\tRequest timed out\t{rtt:.2f} ms")
            result.append('*')
        else:
            if reply.haslayer(ICMP) and reply.getlayer(ICMP).type == 11:
                # Time Exceeded
                print(f"{ttl:<3} {reply.src}\t{rtt:.2f} ms")
                result.append(reply.src)
            elif (use_tcp and reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x12) or \
                 (reply.haslayer(ICMP) and reply.getlayer(ICMP).type == 0):
                # Destination reached
                print(f"{ttl:<3} {reply.src}\t{rtt:.2f} ms\tDestination reached")
                result.append(reply.src)
                break
            else:
                print(f"{ttl:<3} {reply.src}\t{rtt:.2f} ms")
                result.append(reply.src)
    return result


def main():
    parser = argparse.ArgumentParser(description='Python implementation of SolarWinds TraceRouteNG')
    parser.add_argument('host', help='Target host to traceroute')
    parser.add_argument('-p', '--port', type=int, default=80, help='Target port (for TCP mode)')
    parser.add_argument('-m', '--max-ttl', type=int, default=30, help='Maximum TTL')
    parser.add_argument('-t', '--timeout', type=int, default=2, help='Timeout in seconds')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--tcp', action='store_true', help='Use TCP SYN packets')
    group.add_argument('--icmp', action='store_true', help='Use ICMP packets')
    parser.add_argument('-c', '--continuous', action='store_true', help='Continuous traceroute')
    args = parser.parse_args()

    host = args.host
    use_tcp = args.tcp
    previous_result = []

    while True:
        result = traceroute_host(
            host,
            max_ttl=args.max_ttl,
            timeout=args.timeout,
            use_tcp=use_tcp,
            port=args.port
        )

        # Detect path changes
        if previous_result and result != previous_result:
            print("\nPath change detected!")
            print("Previous path:")
            for hop in previous_result:
                print(hop)
            print("\nCurrent path:")
            for hop in result:
                print(hop)
        previous_result = result

        if not args.continuous:
            break
        time.sleep(5) 

if __name__ == '__main__':
    main()
