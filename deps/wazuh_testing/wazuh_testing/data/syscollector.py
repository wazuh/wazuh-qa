# Legacy Syscollector Templates

LEGACY_SYSCOLLECTOR_HEADER = '{"type":"<syscollector_type>",' \
                      '"ID":<random_int>,"timestamp":"<timestamp>"'

LEGACY_SYSCOLLECTOR_OS_EVENT_TEMPLATE = ',"inventory":{"os_name":"<random_string>",' \
                                 '"os_major":"8","os_minor":"3","os_version":"8.3",' \
                                 '"os_platform":"centos","sysname":"Linux",' \
                                 '"hostname":"centos3","release":"4.18.0-240.1.1.el8_3.x86_64",' \
                                 '"version":"#1 SMP Thu Nov 19 17:20:08 UTC 2020","architecture":"x86_64"}}'

LEGACY_SYSCOLLECTOR_HARDWARE_EVENT_TEMPLATE = ',"inventory":{"board_serial":"0",' \
                                       '"cpu_name":"AMD Ryzen 7 3750H with Radeon Vega Mobile Gfx",' \
                                       '"cpu_cores":<random_int>,"cpu_MHz":2295.686,"ram_total":828084,' \
                                       '"ram_free":60488,"ram_usage":93}}'

LEGACY_SYSCOLLECTOR_PACKAGES_EVENT_TEMPLATE = ',"program":{"format":"rpm","name":"<random_string>",' \
                                       '"description":"JSON::XS compatible pure-Perl module",' \
                                       '"size":126,"vendor":"CentOS","group":"Unspecified",' \
                                       '"architecture":"noarch","source":"perl-JSON-PP-2.97.001-3.el8.src.rpm",' \
                                       '"install_time":"2021/03/12 12:23:17"' \
                                       ',"version":"1:2.97.001-3.el8"}}'

LEGACY_SYSCOLLECTOR_PROCESS_EVENT_TEMPLATE = ',"process":{"pid":3150,"name":"<random_string>","state":"R",' \
                                      '"ppid":2965,"utime":58,' \
                                      '"stime":2,"cmd":"rpm","argvs":["-qa","xorg-x11*"],' \
                                      '"euser":"root","ruser":"root","suser":"root","egroup":"ossec",' \
                                      '"rgroup":"ossec","sgroup":"ossec",' \
                                      '"fgroup":"ossec","priority":30,' \
                                      '"nice":10,"size":22681,"vm_size":90724,' \
                                      '"resident":5626,"share":2262,' \
                                      '"start_time":21863,"pgrp":3150,' \
                                      '"session":3150,"nlwp":1,' \
                                      '"tgid":3150,"tty":0,"processor":0}}'

LEGACY_SYSCOLLECTOR_NETWORK_EVENT_TEMPLATE = ',"iface":{"name":"<random_string>","type":"ethernet","state":"up",' \
                                      '"MAC":"08:00:27:be:ce:3a","tx_packets":2135,' \
                                      '"rx_packets":9091,"tx_bytes":210748,' \
                                      '"rx_bytes":10134272,"tx_errors":0,' \
                                      '"rx_errors":0,"tx_dropped":0,"rx_dropped":0,' \
                                      '"MTU":1500,"IPv4":{"address":["10.0.2.15"],' \
                                      '"netmask":["255.255.255.0"],"broadcast":["10.0.2.255"],' \
                                      '"metric":100,"gateway":"10.0.2.2","DHCP":"enabled"}}}'

LEGACY_SYSCOLLECTOR_PORTS_EVENT_TEMPLATE = ',"port":{"protocol":"tcp","local_ip":"0.0.0.0",' \
                                   '"local_port":<random_int>,"remote_ip":"0.0.0.0",' \
                                   '"remote_port":0,"tx_queue":0,' \
                                   '"rx_queue":0,"inode":22273,"state":"listening"}}'

LEGACY_SYSCOLLECTOR_HOTFIX_EVENT_TEMPLATE = ',"hotfix":"<random_string>"}'


# Delta Templates

SYSCOLLECTOR_PACKAGE_DELTA_DATA_TEMPLATE = {
        "architecture":  "<package_architecture>",
        "checksum": "<random_string>",
        "description": "<package_description>",
        "format": "<package_format>",
        "groups": "editors",
        "install_time": "<timestamp>",
        "item_id": "<package_item_id>",
        "location": " ",
        "multiarch":  "null",
        "name": "<package_name>",
        "priority": "optional",
        "scan_time": "2023/12/19 15:32:25",
        "size": "<random_int>",
        "source": "<package_source>",
        "vendor": "<package_vendor>",
        "version": "<package_version>"
}

SYSCOLLECTOR_HOTFIX_DELTA_DATA_TEMPLATE = {
        "checksum": "<random_string>",
        "hotfix": "<random_string>",
        "scan_time": "<timestamp>"
}

SYSCOLLECTOR_OSINFO_DELTA_EVENT_TEMPLATE = {
        "checksum": "1634140017886803554",
        "architecture": "x86_64",
        "hostname": "<agent_name>",
        "os_codename": "focal",
        "os_major": "20",
        "os_minor": "04",
        "os_name": "Ubuntu",
        "os_platform": "ubuntu",
        "os_patch":  "6",
        "os_release": "sp1",
        "os_version": "20.04.6 LTS (Focal Fossa)",
        "os_build": "4.18.0-305.12.1.el8_4.x86_64",
        "release": "6.2.6-76060206-generic",
        "scan_time": "2023/12/20 11:24:58",
        "sysname": "Linux",
        "version": "#202303130630~1689015125~22.04~ab2190e SMP PREEMPT_DYNAMIC"
}

SYSCOLLECTOR_PROCESSSES_DELTA_EVENT_TEMPLATE = {
        "argvs": "<random_int",
        "checksum": "<random_string>",
        "euser": "<random_string>",
        "fgroup": "<random_string>",
        "name": "<random_string>",
        "nice": "<random_int>",
        "nlwp": "<random_int>",
        "pgrp": "<random_int>",
        "ppid": "<random_int>",
        "priority": "<random_int>",
        "processor": "<random_int>",
        "resident": "<random_int>",
        "rgroup": "<random_string>",
        "scan_time": "<timestamp>",
        "session": "<random_int>",
        "sgroup": "<random_string>",
        "share": "<random_int>",
        "size": "<random_int>",
        "start_time": "<random_int>",
        "state": "S",
        "stime": "<random_int>",
        "suser": "<random_string>",
        "tgid": "<random_int>",
        "tty": "<random_int>",
        "utime": "<random_int>",
        "vm_size": "<random_int>",
        "cmd": "",
        "egroup": "<random_string>",
        "ruser": "<random_string>"
}

SYSCOLLECTOR_PORTS_DELTA_EVENT_TEMPLATE = {
        "checksum": "<random_string>",
        "item_id": "<random_string>",
        "local_ip": "0.0.0.0",
        "local_port": "<random_int>",
        "pid": "<random_int>",
        "process": "NULL",
        "protocol": "tcp",
        "remote_ip": "0.0.0.0",
        "remote_port": "<random_int>",
        "rx_queue": "<random_int>",
        "scan_time": "<timestamp>",
        "state": "listening",
        "tx_queue": "<random_int>"
}

SYSCOLLECTOR_HWINFO_DELTA_EVENT_TEMPLATE = {
        "scan_time": "<timestamp>",
        "board_serial": "<random_string>",
        "checksum": "<random_string>",
        "cpu_mhz": "<random_int>",
        "cpu_cores": "<random_int>",
        "cpu_name": "<random_string>",
        "ram_free": "<random_int>",
        "ram_total": "<random_int>",
        "ram_usage": "<random_int>"
}

SYSCOLLECTOR_NETWORK_IFACE_DELTA_EVENT_TEMPLATE = {
        "adapter": None,
        "checksum": "<random_int>",
        "item_id": "<random_int>",
        "mac": "<random_int>",
        "mtu": "<random_int>",
        "name": "<random_int>",
        "rx_bytes": "<random_int>",
        "rx_dropped": "<random_int>",
        "rx_errors": "<random_int>",
        "rx_packets": "<random_int>",
        "scan_time": "<timestamp>",
        "state": "<random_int>",
        "tx_bytes": "<random_int>",
        "tx_dropped": "<random_int>",
        "tx_errors": "<random_int>",
        "tx_packets": "<random_int>",
        "type": "<random_int>"
}

SYSCOLLECTOR_NETWORK_NETADDR_DELTA_EVENT_TEMPLATE = {
    "id": "<random_int>",
    "scan_id": "<random_int>",
    "proto": "<random_string>",
    "address": "192.168.1.87",
    "netmask": "255.255.255.0",
    "broadcast": "192.168.1.255",
    "checksum": "<random_string",
    "item_id": "<random_string>"
}

SYSCOLLECTOR_NETWORK_NETPRO_DELTA_EVENT_TEMPLATE = {
    "id": "<random_int>",
    "scan_id": "<random_int>",
    "iface": "eth0",
    "type": "ipv4",
    "gateway": "192.168.1.1",
    "dhcp": "enabled",
    "checksum": "<random_int>",
    "item_id": "<random_int>"
}
