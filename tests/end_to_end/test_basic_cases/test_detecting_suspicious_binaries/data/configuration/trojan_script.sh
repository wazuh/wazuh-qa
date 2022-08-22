#!/bin/bash
echo "`date` this is evil"   > /tmp/trojan_created_file
echo 'test for /usr/bin/w trojaned file' >> /tmp/trojan_created_file
#Now running original binary
/usr/bin/w.copy
