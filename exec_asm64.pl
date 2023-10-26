#!/usr/bin/perl
#
# exec_asm64.pl: Execute assembly code on Linux x86_64
# written by isra - isra _replace_by_@_ fastmail.net - https://hckng.org
# based on https://gist.github.com/monoxgas/c0b0f086fc7aa057a8256b42c66761c8
# version 0.1 - october 2023
#

use B;
use Config;
use 5.008001;
use DynaLoader;

# memory map
sub mmap {
    # syscall number for mmap is 9 on Linux x86_64
    # $addr can be a fixed value, or 0 to let mmap choose one
    # it returns a pointer to the mapped area on success, -1 on failure
    my ($addr, $size, $protect, $flags) = @_;
    my $ret = syscall(9, $addr, $size, $protect, $flags, -1, 0);
    return $ret;
}

# memory protect
sub mprotect {
    # syscall number for mprotect is 10 on Linux x86_64
    # it returns 0 on success, -1 on failure
    my ($addr, $size, $protect) = @_;
    my $ret = syscall(10, $addr, $size, $protect);
    return $ret;
}

# copy $bytes of length $len into address $location
sub poke {
    my($location, $bytes, $len) = @_;
    my $dummy = 'X' x $len;
    my $dummy_addr = \$dummy + 0;

    my $size = 16 + $Config{ivsize};
    my $ghost_sv_contents = unpack("P".$size, pack("Q", $dummy_addr));
    substr( $ghost_sv_contents, 16, $Config{ivsize} ) = pack("Q", $location);

    my $ghost_string_ref = bless( \ unpack(
        "Q",
        do { no warnings 'pack'; pack( 'P', $ghost_sv_contents.'' ) },
    ), 'B::PV' )->object_2svref;

    eval 'substr($$ghost_string_ref, 0, $len) = $bytes';
}

# payload to execute /usr/bin/id with execve (x86_64)
my $payload = "";
$payload .= "\xe8\x0d\x00\x00\x00\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x69";
$payload .= "\x64\x00\x5e\x5e\x48\x31\xc0\x48\x8d\x3e\x6a\x00\x57\x48\x89";
$payload .= "\xe6\x48\x31\xc0\xb8\x3b\x00\x00\x00\xba\x00\x00\x00\x00\x0f";
$payload .= "\x05\x5e\x48\x31\xd2\xb8\x3c\x00\x00\x00\x0f\x05";

print "\n";
print "*" x 39;
print "\n* exec_asm64.pl - by isra - hckng.org *\n";
print "*" x 39;
print "\n\n";

my $size = length($payload);
print "[+] Payload size: $size\n";
print "[+] Trying to map new memory area...";
my $ptr = mmap(0, $size, 3, 33);
if($ptr == -1) {
    die "failed to map memory\n";
}
print "OK\n";
printf("[+] Start of mapped area: 0x%x\n", $ptr);

printf("[+] Trying to POKE payload at 0x%x...", $ptr);
poke($ptr, $payload, $size);
print "OK\n";

print "[+] Trying to update memory protection...";
if(mprotect($ptr, $size, 5) == -1) {
    die "failed to update memory protection\n";
}
print "OK\n";

print "[+] Trying to install xsub...";
my $func = DynaLoader::dl_install_xsub(
    "_japh", # not really used
    $ptr, 
    __FILE__ # no file
);
print "OK\n";

print "[+] Going to execute:\n\n";

# dereference and execute
&{$func};
