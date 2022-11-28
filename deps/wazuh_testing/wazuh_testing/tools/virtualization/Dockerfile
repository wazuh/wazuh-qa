FROM ubuntu
RUN apt-get update && \
apt-get install -y curl gnupg2 && \
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list && \
apt-get update && \
apt-get install -y wazuh-agent && \
rm -rf /var/lib/apt/lists/* 
RUN rm -f /var/ossec/etc/ossec.conf
ADD --chown=root:wazuh ossec.conf /var/ossec/etc
CMD /var/ossec/bin/wazuh-control start && tail -f /dev/null
