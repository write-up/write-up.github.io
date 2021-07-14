# CVE-2021-35064 Privilege escalation in VIAware
 
 The VIAware web application runs as www-data, however the sudoers configuration provides several ways for an attacker to gain root access.
 
 
 User www-data may run the following commands on TESTHOST:
     (root) NOPASSWD: /usr/bin/unzip, /usr/bin/gconftool-2, /usr/bin/pkill, /bin/systemctl, /usr/bin/dpkg, /usr/bin/dpkg-deb
 
 
 There are numerous ways to exploit these commands to gain root access, for example dpkg could be used to install a malicious package, systemctl can be used to edit and run services, and unzip can be used to unpack a SUID-binary which trivially provides a root shell.

CVE-2021-36356 Unauthenticated Remote Code Execution in VIAware
---------------------------------------------------------------

 The vulnerability is essentially the same as CVE-2019-17124, which the vendor claims was fixed in earlier versions, however upon testing the actual vulnerable endpoint still exists in the tested versions even though the GUI for the vulnerable mechanism has now been removed.
 
 By sending a crafted request to /ajaxPages/writeBrowseFilePathAjax.php an attacker is able to write arbitrary content to any path writable by the www-data user, including paths under the web root. This is trivially exploited by planting a .php file.
