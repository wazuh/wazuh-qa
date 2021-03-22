SYSCOLLECTOR_HEADER = '{"type":"<syscollector_type>",' \
                      '"ID":<random_int>,"timestamp":"<timestamp>"'

SYSCOLLECTOR_OS_EVENT_TEMPLATE = ',"inventory":{"os_name":"<random_string>",' \
                                 '"os_major":"8","os_minor":"3","os_version":"8.3",' \
                                 '"os_platform":"centos","sysname":"Linux",' \
                                 '"hostname":"centos3","release":"4.18.0-240.1.1.el8_3.x86_64",' \
                                 '"version":"#1 SMP Thu Nov 19 17:20:08 UTC 2020","architecture":"x86_64"}}'

SYSCOLLECTOR_HARDWARE_EVENT_TEMPLATE = ',"inventory":{"board_serial":"0",' \
                                       '"cpu_name":"AMD Ryzen 7 3750H with Radeon Vega Mobile Gfx",' \
                                       '"cpu_cores":<random_int>,"cpu_MHz":2295.686,"ram_total":828084,' \
                                       '"ram_free":60488,"ram_usage":93}}'

SYSCOLLECTOR_PACKAGES_EVENT_TEMPLATE = ',"program":{"format":"rpm","name":"<random_string>",' \
                                       '"description":"JSON::XS compatible pure-Perl module",' \
                                       '"size":126,"vendor":"CentOS","group":"Unspecified",' \
                                       '"architecture":"noarch","source":"perl-JSON-PP-2.97.001-3.el8.src.rpm",' \
                                       '"install_time":"2021/03/12 12:23:17"' \
                                       ',"version":"1:2.97.001-3.el8"}}'

SYSCOLLECTOR_PROCESS_EVENT_TEMPLATE = ',"process":{"pid":3150,"name":"<random_string>","state":"R","ppid":2965,"utime":58,' \
                                      '"stime":2,"cmd":"rpm","argvs":["-qa","xorg-x11*"],' \
                                      '"euser":"root","ruser":"root","suser":"root","egroup":"ossec",' \
                                      '"rgroup":"ossec","sgroup":"ossec",' \
                                      '"fgroup":"ossec","priority":30,' \
                                      '"nice":10,"size":22681,"vm_size":90724,' \
                                      '"resident":5626,"share":2262,' \
                                      '"start_time":21863,"pgrp":3150,' \
                                      '"session":3150,"nlwp":1,' \
                                      '"tgid":3150,"tty":0,"processor":0}}'

SYSCOLLECTOR_NETWORK_EVENT_TEMPLATE = ',"iface":{"name":"<random_string>","type":"ethernet","state":"up",' \
                                      '"MAC":"08:00:27:be:ce:3a","tx_packets":2135,' \
                                      '"rx_packets":9091,"tx_bytes":210748,' \
                                      '"rx_bytes":10134272,"tx_errors":0,' \
                                      '"rx_errors":0,"tx_dropped":0,"rx_dropped":0,' \
                                      '"MTU":1500,"IPv4":{"address":["10.0.2.15"],' \
                                      '"netmask":["255.255.255.0"],"broadcast":["10.0.2.255"],' \
                                      '"metric":100,"gateway":"10.0.2.2","DHCP":"enabled"}}}'

SYSCOLLECTOR_PORT_EVENT_TEMPLATE = ',"port":{"protocol":"tcp","local_ip":"0.0.0.0",' \
                                   '"local_port":<random_int>,"remote_ip":"0.0.0.0",' \
                                   '"remote_port":0,"tx_queue":0,' \
                                   '"rx_queue":0,"inode":22273,"state":"listening"}}'

SYSCOLLECTOR_HOTFIX_EVENT_TEMPLATE = ',"hotfix":"<random_string>"}'

