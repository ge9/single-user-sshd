use strict;
use warnings;
use Socket;
use IPC::Open2;

select(STDERR); $| = 1;

sub log_msg { print STDERR "[". scalar(localtime) . "] $_[0]\n"; }

my ($msys_path, $pipe_path) = @ARGV;
die "Usage: npipe-proxy.pl <sock_path> <pipe_path>\n" unless $msys_path && $pipe_path;

unlink($msys_path) if -e $msys_path;

socket(my $server, PF_UNIX, SOCK_STREAM, 0) or die "socket failed: $!\n";
bind($server, sockaddr_un($msys_path))       or die "bind failed: $!\n";
listen($server, 10)                         or die "listen failed: $!\n";

# log_msg("SUCCESS: Listening on $msys_path -> $pipe_path");

while (accept(my $client, $server)) {
    # log_msg("ACCEPTED: New client connected");
    
    my $pid = fork();
    if (defined $pid && $pid == 0) {
        close($server);

        my ($relay_out, $relay_in);
        my $relay_pid = eval { open2($relay_out, $relay_in, "npiperelay.exe", "-ep", "-s", $pipe_path) };
        if (!$relay_pid) {
            log_msg("ERROR failed to spawn npiperelay: $@");
            exit 1;
        }

        select($client);   $| = 1;
        select($relay_in); $| = 1;

        my $fn_client    = fileno($client);
        my $fn_relay_out = fileno($relay_out);

        my $rin = "";
        vec($rin, $fn_client, 1)    = 1;
        vec($rin, $fn_relay_out, 1) = 1;

        while (1) {
            my $rout = $rin;
            my $nfound = select($rout, undef, undef, undef);
            last if $nfound <= 0;

            if (vec($rout, $fn_client, 1)) {
                my $buf = "";
                my $len = sysread($client, $buf, 4096);
                last if !defined $len || $len == 0;
                syswrite($relay_in, $buf);
            }
            if (vec($rout, $fn_relay_out, 1)) {
                my $buf = "";
                my $len = sysread($relay_out, $buf, 4096);
                last if !defined $len || $len == 0;
                syswrite($client, $buf);
            }
        }

        close($relay_in);
        close($relay_out);
        # log_msg("CHILD: Connection closed");
        exit(0);
    }
    close($client);
}