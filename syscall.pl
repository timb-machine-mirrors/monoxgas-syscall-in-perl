use DynaLoader;
use Devel::Peek;
use Fcntl;
use 5.008001; # because 5.6 doesn't have B::PV::object_2svref
use Config;
use B (); # for B::PV

sub mmap {
  my ($addr, $size, $protect, $flags) = @_;
  syscall(197, $addr, $size, $protect, $flags, -1, 0);
}

sub mmap_with_fd {
  my ($addr, $size, $protect, $flags, $fd) = @_;
  syscall(197, $addr, $size, $protect, $flags, $fd, 0);
}

sub mprotect {
  my ($addr, $size, $protect) = @_;
  syscall(74, $addr, $size, $protect);
}

sub shm_open {
  my ($name, $flags, $mode) = @_;
  syscall(266, $name, $flags, $mode);
}

sub ftruncate {
  my ($fd, $length) = @_;
  syscall(201, $fd, $length);
}

print "\nPerl $] in [$$]\n";
print("\n---\n");

my $name = "/myshm12";
my $length = 4096;

$addr = 4096 * 10000000;
$truncated_addr = mmap($addr, $length, 7, hex '0x1012');
printf("addr: 0x%X/%d\n", $addr, $addr);
printf("truncated_addr: 0x%X\n", $truncated_addr);

$str = "Hello world.\n\n";
printf("&str: 0x%X\n", SVPtr($str));
printf("str_len: 0x%X", CPtr(length($str)));

my $asmcode = "\x90";
$asmcode .= "\x48\xc7\xc0\x04\x00\x00\x02"; # mov  rax, 0x2000004
$asmcode .= "\x48\xc7\xc7\x01\x00\x00\x00"; # mov  rdi, 0x1 ; stdout
$asmcode .= "\x48\xbe" .  CPtr($str);
$asmcode .= "\x48\xc7\xc2" .  CInt(length($str));
$asmcode .= "\x0f\x05";
$asmcode .= "\xc3";

poke($addr, $asmcode);
print("\n---\n");

print "\n[+] Making syscall:\n";
my $func = DynaLoader::dl_install_xsub("_Testing", $addr, __FILE__);  
&{$func};

sub SVPtr{
 return unpack("Q",pack("p",$_[0]));
}
sub CPtr{
 return pack("p",$_[0]);
}
sub CInt{
 return pack("i",$_[0]);
}
sub CShort{
 return pack("s",$_[0]);
}
sub CByte{
 return pack("c",$_[0]);
}
sub CDbl{
 return pack("d",$_[0]);
}
sub CQuad{  # emulates pack("Q",...) - assumes decimal string input
# --- convert an arbitrary length decimal string to a hex string ---
 my @digits = split(//, $_[0]);
 my $lohexstr = substr(sprintf("%08X",substr($_[0],-8)),-2);  # gets the first 8 bits 
 my $totquotient = ""; 
# bit shift to the right 8 bits by dividing by 256,
# using arbitrary precision grade school long division
for (my $j = 0;$j <4 ; ++$j){  # shift 8 bits, 4 times for lower long
 my $remainder = "";
 $totquotient = "";
 my $quotient = "";
 my $dividend = "";
 my $remainder = "";
 for(my $i=0;$i<=$#digits;++$i){  
  $dividend = $remainder . $digits[$i];
  $quotient = int($dividend/256);
  $remainder = $dividend % 256; 
  $totquotient .= sprintf("%01d",$quotient);
 }
 $totquotient =~ s/^0*//;
 last if $j==3;
 $lohexstr = substr(sprintf("%08X",substr($totquotient,-8)),6,2) . $lohexstr; # unshift 8 more bits
 @digits = split(//,$totquotient); 
} 
 my $hihexstr = sprintf("%08X",$totquotient);
 my $lo = pack("H*",  $lohexstr);
 my $hi = pack("H*",  $hihexstr); 
 ( $hi, $lo ) = ( $lo, $hi ) ; # little endian
 return $hi . $lo;  
}
sub SVQuad{  # emulates unpack("Q",...) - assumes binary input 
 my ($hi, $lo) = unpack("NN",$_[0]) ;
 ( $hi, $lo ) = ( $lo, $hi )   ; # little endian
 return sprintf("0x%08X%08X",$hi,$lo); # - Are 64 bit decimal expressions meaningful ?
}
sub _pack_address {
  my $p = pack("Q", $_[0]);
  return $p;
}
sub peek {
  unpack "P$_[1]", _pack_address($_[0]);
}
sub poke {
  my($location, $bytes) = @_;
  # sanity check is (imho) warranted as described here:
  # http://blogs.perl.org/users/aristotle/2011/08/utf8-flag.html#comment-36499
  if (utf8::is_utf8($bytes) and $bytes  =~ /([^\x00-\x7F])/) {
    croak( ord($1) > 255
      ? "Expecting a byte string, but received characters"
      : "Expecting a byte string, but received what looks like *possible* characters, please utf8_downgrade the input"
    );
  }
  # this should be constant once we pass the regex check above... right?
  my $len = length($bytes);
  my $addr = _pack_address($location);
  # construct a B::PV object, backed by a SV/SvPV to a dummy string length($bytes)
  # long, and substitute $location as the actual string storage
  # we specifically use the same length so we do not have to deal with resizing
  my $dummy = 'X' x $len;
  my $dummy_addr = \$dummy + 0;
  my $ghost_sv_contents = peek($dummy_addr, 8 + 4 + 4 + $Config{ivsize});
  substr( $ghost_sv_contents, 8 + 4 + 4, 8 ) = $addr;
  my $ghost_string_ref = bless( \ unpack(
    "Q",
    # it is crucial to create a copy of $sv_contents, and work with a temporary
    # memory location. Otherwise perl memory allocation will kick in and wreak
    # considerable havoc culminating with an inevitable segfault
    do { no warnings 'pack'; pack( 'P', $ghost_sv_contents.'' ) },
  ), 'B::PV' )->object_2svref;
  # now when we write to the newly created "string" we are actually writing
  # to $location
  # note we HAVE to use lvalue substr - a plain assignment will add a \0
  #
  # Also in order to keep threading on perl 5.8.x happy we *have* to perform this
  # in a string eval. I don't have the slightest idea why :)
  eval 'substr($$ghost_string_ref, 0, $len) = $bytes';
  return $len;
}