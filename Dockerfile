FROM freeradius/freeradius-server:3.2.7-alpine

# Our config overrides (image config lives in /etc/raddb -> /opt/etc/raddb)
COPY raddb/clients.conf                     /etc/raddb/clients.conf
COPY raddb/mods-available/eap               /etc/raddb/mods-available/eap
COPY raddb/mods-available/blocked_devices   /etc/raddb/mods-available/blocked_devices
COPY raddb/mods-available/panel_authlog      /etc/raddb/mods-available/panel_authlog
COPY raddb/sites-available/check-eap-tls    /etc/raddb/sites-available/check-eap-tls
COPY radius/run.sh                          /usr/local/bin/radius-run.sh

RUN ln -sf ../mods-available/blocked_devices /etc/raddb/mods-enabled/blocked_devices \
 && ln -sf ../mods-available/panel_authlog    /etc/raddb/mods-enabled/panel_authlog \
 && ln -sf ../sites-available/check-eap-tls  /etc/raddb/sites-enabled/check-eap-tls \
 # Log accept/reject lines for the admin panel (post-auth = accept, REJECT block = reject)
 && awk '/^post-auth \{/ && !a {print; print "\tpanel_authlog_accept"; a=1; next} /^[[:space:]]*Post-Auth-Type REJECT \{/ && !b {print; print "\t\tpanel_authlog_reject"; b=1; next} {print}' /etc/raddb/sites-available/default > /tmp/default \
 && cat /tmp/default > /etc/raddb/sites-available/default && rm /tmp/default \
 && grep -q panel_authlog_accept /etc/raddb/sites-available/default \
 && grep -q panel_authlog_reject /etc/raddb/sites-available/default \
 && sed -i -E 's/^([[:space:]]*)auth = no/\1auth = yes/' /etc/raddb/radiusd.conf \
 && mkdir -p /etc/raddb/panel-dyn /var/log/wifi-radius /var/run/wifi-radius-control

ENTRYPOINT ["/usr/local/bin/radius-run.sh"]
