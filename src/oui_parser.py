def get_mac_vendor(oui):
    # skip first line
    if oui.readline() == '':
        return None

    # extract mac and vendor info
    mac, vendor = oui.readline().rstrip().split('\t\t')
    mac = mac.split(' ')[0]

    # skip address
    while True:
        line = oui.readline()
        if line == '\n' or line == '':
            break

    return mac, vendor

def parse_oui(oui_file):
    parsed = {}

    with open(oui_file) as oui:
        # just skip first 4 lines
        for i in range(4):
            oui.readline()

        while True:
            res = get_mac_vendor(oui)
            if res == None:
                break
            mac, vendor = res
            parsed[mac.lower()] = vendor

    return parsed

