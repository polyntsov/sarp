import argparse
import sniffer

def parse_args():
    parser = argparse.ArgumentParser(description="ARP packets sniffer.")
    parser.add_argument("-i", "--interface", type=str, dest="interface",
                        help="the name of the interface on which to sniff packets"
                             " (sniffs on all interfaces by default)")
    return parser.parse_args()

def main():
    args = parse_args()
    sniffer.Config.interface = args.interface
    sniffer.sniff()

if __name__ == "__main__":
    main()
