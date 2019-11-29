<b> Update: </b>According to TitanHQ, the issues mentioned below have been resolved in version 5.18.

# A quick look at WebTitan
A while ago a colleague of mine spotted some suspicious traffic while monitoring a network. The traffic appeared to be the plaintext download of a shellscript, and it turned out that the script was being downloaded by an appliance known as "SpamTitan". The script was downloaded over HTTP and automatically run as root, so we reported it and you can read more about it [here](https://write-up.github.io/CVE-2019-6800/).

After finding the pretty silly vulnerability, combined with the lackluster fix provided by TitanHQ, I decided to do some further digging into these appliances as I kept running into them in various places - the SpamTitan solution appears to be pretty popular amongst certain MSP's, and if it's running random code as root there must be more fun stuff to find. This write-up summarizes findings in the "WebTitan" proxy appliance.

## Starting out
For anyone else looking at the Spam/WebTitan software, it appears to be a loosely glued together collection of PHP, shellscripts and open source software, running on  FreeBSD. A lot of the PHP is obfuscated using IonCube, and so I haven't bothered looking at it too much, but based on the things I did see I reckon there are web vulnerabilities to be found if anyone spends some time on the web interface.

## Arbitrary code execution as root (exact same attack as CVE-2019-6800 linked above) (CVE-2019-19019)
So, right out of the gate, we find /usr/local/etc/periodic/daily/wt-hotfix.sh which contains the same vulnerability as we found in SpamTitan. The code downloads a shellscript via HTTP and executes it as root.

```
hotfix=`/usr/local/bin/wget -nv -m http://download.webtitan.com/hotfix/${product}/${version}/hotfix.sh 2>&1 | grep -c download`
if [ $hotfix -eq 1 ]; then
        if [ -f ./download.webtitan.com/hotfix/${product}/${version}/hotfix.sh ]; then
                /bin/chmod +x ./download.webtitan.com/hotfix/${product}/${version}/hotfix.sh
                ./download.webtitan.com/hotfix/${product}/$version/hotfix.sh
        fi
fi
```

As they received notice of the vulnerability in their other appliance about 6 months ago, and released a fix over 3 months ago, this is concerning.


## Database access via proxy service (Unauthenticated Remote Code Execution) (CVE-2019-19015)
As the primary purpose of the WebTitan appliance appears to be proxying traffic for users, it exposes a proxy service (squid) on TCP/8881. By default, this proxy allows users to connect to local ports on the WebTitan appliance itself, including TCP/5432.

![](examples/proxy-database.gif?raw=true)

By simply proxying the SQL connection it is possible to log into the database without a password using the "titax" or "pgsql" accounts. With this database connection we can alter any table we want, including the `admins` table which contains all admin accounts (more on this table later) - by inserting our own account we can now gain administrative access to the web interface.

As we are logged in as pgsql we can also execute arbitrary commands as the pgsql user:

![](examples/database-exec.gif?raw=true)

Unfortunately the pgsql user can't actually do all that much, except of course read / modify all the contents of the DB and accounts. But we want root.

# Exploiting the backup restore function (Authenticated Remote Code Execution) (CVE-2019-19020)
The web interface exposes a function where a logged in administrator can export and import backups. When exporting we receive a .tar.bz2 file which contains a couple of different files, including some under var/tmp which appear to be the databases. At first I tried downloading this and simply adding some fun files under the web root, but I quickly realized the backup function was broken - even without tampering the interface would just return "error 7" whenever I tried to upload it.

By reviewing the wt-backup.pl script found under /usr/local/bin I was able to find the bug, and create my own backup construction script which would allow me to build a functioning backup, which I could then inject malicious code into.

![](examples/backup-exploit.gif?raw=true)

Voilá, we now have a web shell, and are running as `www`. Why this is much more fun than running as `pgsql` will become clear shortly.

## One last note on the Remote Code Execution 
Funnily enough the first script we noted (wt-hotfix.sh) grabs proxy settings from the database. Essentially this means that besides our two already described vectors of RCE we can actually modify the database to have the appliance fetch the scripts to run as root via our proxy out on the public Internet without even having to intercept and MITM any traffic.

Pretty neat, as it's run as root anyway so we can just skip the privesc, but let's pretend like we still need it just for fun.

## Privilege Escalation (CVE-2019-19014)
Once we have a shell through the backup function trick, we need to escalate our privileges - luckily the sudoers file is extremely generous. `www` is permitted to run somewhere around 43 commands as root, including `chown` and `chmod`, so just chown and setuid or something. There are hundreds of other ways probably, look for yourselves.

```
# sudoers file.
#
# This file MUST be edited with the 'visudo' command as root.
# Failure to use 'visudo' may result in syntax or file permission errors
# that prevent sudo from running.
#
# See the sudoers man page for the details on how to write a sudoers file.
#

# Host alias specification

# User alias specification

# Cmnd alias specification

# Defaults specification
# Uncomment if needed to preserve environmental variables related to the
# FreeBSD pkg_* utilities.
#Defaults	env_keep += "PKG_PATH PKG_DBDIR PKG_TMPDIR TMPDIR PACKAGEROOT PACKAGESITE PKGDIR"

# Uncomment if needed to preserve environmental variables related to
# portupgrade. (portupgrade uses some of the same variables as the pkg_*
# tools so their Defaults above should be uncommented if needed too.)
#Defaults	env_keep += "PORTSDIR PORTS_INDEX PORTS_DBDIR PACKAGES PKGTOOLS_CONF"

# Runas alias specification

Runas_Alias DB = pgsql

# User privilege specification
root	ALL=(ALL) ALL

# Uncomment to allow people in group wheel to run all commands
# %wheel	ALL=(ALL) ALL

# Same thing without a password
# %wheel	ALL=(ALL) NOPASSWD: ALL

# Samples
# %users  ALL=/sbin/mount /cdrom,/sbin/umount /cdrom
# %users  localhost=/sbin/shutdown -h now
www ALL=NOPASSWD: /blocker/bin/perl_www.pl
webtitan ALL=NOPASSWD: /blocker/bin/perl_exec.pl
webtitan ALL=NOPASSWD: /usr/local/etc/rc.d/samba_server
webtitan ALL=NOPASSWD: /usr/local/etc/rc.d/apache22
webtitan ALL=NOPASSWD: /usr/local/etc/rc.d/apache24
webtitan ALL=NOPASSWD: /bin/mv
webtitan ALL=NOPASSWD: /bin/rm
webtitan ALL=NOPASSWD: /bin/cp
webtitan ALL=NOPASSWD: /blocker/proxy/sbin/proxy
webtitan ALL=NOPASSWD: /sbin/shutdown
webtitan ALL=NOPASSWD: /blocker/bin/ntp_sync
webtitan ALL=NOPASSWD: /bin/pkill
webtitan ALL=NOPASSWD: /usr/sbin/chown
webtitan ALL=NOPASSWD: /usr/bin/chgrp
webtitan ALL=NOPASSWD: /bin/chmod
webtitan ALL=NOPASSWD: /bin/mkdir
webtitan ALL=NOPASSWD: /bin/hostname
webtitan ALL=NOPASSWD: /blocker/bin/timeout
webtitan ALL=NOPASSWD: /etc/rc.d/netif
webtitan ALL=NOPASSWD: /etc/rc.d/routing
webtitan ALL=NOPASSWD: /etc/rc.d/ntpd
webtitan ALL=NOPASSWD: /usr/local/etc/rc.d/clamav-clamd
webtitan ALL=NOPASSWD: /usr/local/bin/net
webtitan ALL=NOPASSWD: /usr/local/bin/freshclam
webtitan ALL=NOPASSWD: /etc/rc.d/ipfw
webtitan ALL=NOPASSWD: /etc/rc.d/natd
webtitan ALL=NOPASSWD: /sbin/ipfw
webtitan ALL=NOPASSWD: /sbin/ifconfig
webtitan ALL=NOPASSWD: /usr/local/bin/wbinfo
webtitan ALL=NOPASSWD: /blocker/tnamed/run.sh
webtitan ALL=NOPASSWD: /blocker/tnamed/stop.sh
webtitan ALL=NOPASSWD: /bin/kill
webtitan ALL=NOPASSWD: /usr/local/etc/rc.d/snmpd
webtitan ALL=NOPASSWD: /usr/local/bin/svc
webtitan ALL=NOPASSWD: /usr/local/etc/rc.d/postgresql
webtitan ALL=NOPASSWD: /usr/local/bin/reghttpcfg.php
webtitan ALL=NOPASSWD: /usr/bin/find
webtitan ALL=NOPASSWD: /etc/rc.d/syslogd
webtitan ALL=NOPASSWD: /usr/sbin/ntpdate

www ALL=NOPASSWD: /bin/kill
www ALL=NOPASSWD: /usr/local/bin/wt-webcert.php
www ALL=NOPASSWD: /bin/cp
www ALL=NOPASSWD: /bin/date
www ALL=NOPASSWD: /etc/rc.d/cron
www ALL=NOPASSWD: /usr/local/bin/ssh
www ALL=NOPASSWD: /usr/local/bin/scp
www ALL=NOPASSWD: /usr/local/bin/wtupdate.php
www ALL=NOPASSWD: /usr/local/etc/rc.d/apache22
www ALL=NOPASSWD: /usr/local/etc/rc.d/apache24
www ALL=NOPASSWD: /bin/ps
www ALL=NOPASSWD: /usr/bin/touch
www ALL=NOPASSWD: /bin/mkdir
www ALL=NOPASSWD: /bin/rm
www ALL=NOPASSWD: /bin/chmod
www ALL=NOPASSWD: /sbin/shutdown
www ALL=NOPASSWD: /etc/rc.d/syslogd
www ALL=NOPASSWD: /usr/sbin/ntpdate
www ALL=NOPASSWD: /usr/local/bin/wt-killssh.sh
www ALL=NOPASSWD: /usr/bin/bunzip2
www ALL=NOPASSWD: /usr/bin/tar
www ALL=NOPASSWD: /usr/local/etc/rc.d/postgresql
www ALL=NOPASSWD: /usr/local/bin/wtpasswd
www ALL=NOPASSWD: /blocker/proxy/sbin/proxy
www ALL=NOPASSWD: /bin/pkill
www ALL=NOPASSWD: /blocker/bin/proxy_auth.pl
www ALL=NOPASSWD: /etc/ipfw.rules
www ALL=NOPASSWD: /usr/local/etc/rc.d/snmpd
www ALL=NOPASSWD: /usr/local/sbin/httpd
www ALL=NOPASSWD: /usr/local/bin/dt-backup.pl
www ALL=NOPASSWD: /usr/local/bin/wt-backup.pl
www ALL=NOPASSWD: /usr/local/bin/svc
www ALL=NOPASSWD: /bin/echo
www ALL=NOPASSWD: /bin/ln
www ALL=NOPASSWD: /usr/sbin/chown
www ALL=NOPASSWD: /usr/blocker/proxy/libexec/ssl_crtd
www ALL=NOPASSWD: /blocker/bin/wt-lic-cache-refresh.php
www ALL=NOPASSWD: /usr/sbin/newsyslog
www ALL=NOPASSWD: /usr/local/bin/wt-checkdynip.php
www ALL=NOPASSWD: /usr/local/bin/upd-default-machine-ssl-cert.php
www ALL=NOPASSWD: /bin/mv
www ALL=(DB) NOPASSWD: ALL

admin ALL=NOPASSWD: /bin/echo
admin ALL=NOPASSWD: /bin/mv
admin ALL=NOPASSWD: /bin/rm
admin ALL=NOPASSWD: /sbin/ifconfig
admin ALL=NOPASSWD: /sbin/mount
admin ALL=NOPASSWD: /sbin/reboot
admin ALL=NOPASSWD: /sbin/route
admin ALL=NOPASSWD: /sbin/shutdown
admin ALL=NOPASSWD: /sbin/umount
admin ALL=NOPASSWD: /tmp/vmware-tools-distrib/vmware-install.pl
admin ALL=NOPASSWD: /usr/local/bin/ssh
admin ALL=NOPASSWD: /usr/local/bin/scp
admin ALL=NOPASSWD: /usr/local/bin/wt-killssh.sh
admin ALL=NOPASSWD: /usr/local/etc/rc.d/apache22
admin ALL=NOPASSWD: /usr/local/etc/rc.d/apache24
admin ALL=NOPASSWD: /usr/local/bin/reghttpcfg.php
```

## The "support" account (Hard-coded administrative password) (CVE-2019-19021)
After gaining access to the database through the issue above, a new account was found named "support". The account appears to be auto-created on installation, but didn't show up in the "Management" -> "Administrators" section of the interface, so it isn't easily noticed. Since we're *extremely* lazy and the hash isn't found on Google we didn't even bother cracking it, but luckily it turned up when we were randomly browsing the file system.

![](examples/support-account.gif)

Using this password, you can log in as an administrator on any appliance assuming you have access to the web interface... and if you can talk to the proxy, you can tunnel to the interface, so this essentially means all users can log in as admins. It's also my impression that this password isn't easily changed - as it doesn't show up in our GUI we reckon logging in as "support" or changing the DB are the primary ways to do it.

Again, this can result in code execution using the same backup-execution technique as the DB issue.

## SQL Injection (CVE-2019-19016)
The page /history-x.php is vulnerable to SQL injection in the "results"-parameter. Didn't spend too much time investigating this, but the following PoC will return JSON if there are more than 0 users, and return an empty body if there aren't.

`/history-x.php?getHistory&results=(SELECT+CASE+WHEN+((SELECT+COUNT(*)+FROM+users)%3E0)+THEN+1+ELSE+-1+END)&faction=0&save=0&gettotalrecords=0`

## Hard-coded root password (CVE-2019-19017)
During the installation process, a sed-script found at /tmp/wtinstall.sed sets a hard-coded hash as the root password. Since root login isn't permitted remotely by default it might not really make a huge difference, but it's a neat way to have privilege escalation on any device you do manage to log on to.

`/tmp/wtinstall.sed`:

```
3,3d
2a\
root:$1$QmzXNacZ$7IEefuHZZNMg72oko7u9q0:0:0::0:0:Charlie &:/root:/bin/csh
```

## Observation 0: Weirdo support connection
Digging around the mess of scripts which is most of the functionality we found what appears to be the support connection function (along with a private SSH key used to connect). The entire support connection appears to revolve around the following commands (/usr/local/bin/wt-squidmon.sh)

```
14:ssh="webtitan@support.webtitan.com";
36:/usr/local/bin/sudo /usr/local/bin/scp -q -P8822 -i /usr/home/admin/.ssh/tunnel ${ssh}:opentunnels.list ${tmpfname}
49:/usr/local/bin/sudo /usr/local/bin/ssh -p 8822 -i /usr/home/admin/.ssh/tunnel $ssh -fNT -R $port:localhost:22 > /dev/null 2>&1
```

Let's dissect the two last lines.

Line 36 copies a file from the server at "support.webtitan.com" which from the name alone appears to be a list of all currently opened support connections, likely including those of other customers. The list is fetched to make sure that line 49 doesn't collide with any of the existing ones (although there is no guard against a race condition here).

Line 49 sets up a reverse SSH tunnel, which basically forwards connections to the customer appliance SSH port from the remote host. Due to the legality of things we never actually connected to the WebTitan support server, however the setup is a bit concerning for several reasons. Unless the server is explicitly configured to disallow traffic forwarding then it's possible that anybody could SSH to other connected customers. Again, we did not verify this but TitanHQ should look into that.

A second reason this is a bit concerning is that based on public sources, the system being connected to isn't exactly Fort Knox. At the time of writing the hostname resolves to 89.101.246.122, which according to Shodan hasn't received security updates since some time around 2016 - https://www.shodan.io/host/89.101.246.122

## Observation 1: Hard-coded authorized SSH key
The admin user has a key added to `.ssh/authorized_keys` with the ID field `root@src_wt.webtitan.com`. Might not be considered a problem by some, but I prefer controlling who can / cannot access machines in my network so I'll mention it anyway.

## Observation 2: ssh-dss explicitly enabled in /root/.ssh/config
The title pretty much says it all. The config applies only to the host support.webtitan.com, which is used for the "secure" support connection, and while it might not be a huge deal, ssh-dss has been deprecated by OpenSSH as outlined here https://www.openssh.com/legacy.html.

## Observation 3: Database config files under webroot (CVE-2019-19018)
An .ini file is reachable under the admin interface web service which reveals the database username - not a huge deal, as it's always set to titax as far as we know.
http://wt/include/dbconfig.ini

## Observation 4: SQL injection on first boot?
Some of the rc.d scripts seem to be constructed to auto-configure for AWS and Azure environments - what they essentially do is fetch unsanitized data from 169.254.169.254 and use this data in various SQL queries. While it's not a huge attack surface, people really ought to secure their scripts to avoid this type of potential issue.

## Observation 5: cachemgr XSS
Using the proxying trick described above we could access the cachemanager web interface of Squid, where we found a Cross-Site Scripting issue. Just as this summary was being written CVE-2019-13345 was publicized, discussed here `https://bugs.squid-cache.org/show_bug.cgi?id=4957`.

WebTitan is likely still vulnerable to it though until they patch Squid.
