#!/usr/local/cpanel/3rdparty/bin/perl
# s3-mirror-sets.pl — upload existing local cPanel backup sets to the configured
# remote destination, using cPanel's own transport stack (same layout, same
# credentials, same multipart upload code the nightly transporter uses).
#
#   dry-run (default):  s3-mirror-sets.pl /backup/2026-07-22 /backup/weekly/2026-07-19
#   apply:              s3-mirror-sets.pl --apply /backup/2026-07-2* /backup/weekly/* /backup/monthly/*
#
# Remote path = <destination folder>/<path of the set relative to BACKUPDIR>/...
#   /backup/2026-07-22/accounts/x.tar.gz        -> /serverk01/2026-07-22/accounts/x.tar.gz
#   /backup/weekly/2026-07-19/system/system_files.tar -> /serverk01/weekly/2026-07-19/system/system_files.tar
#
# Files already present on the remote with the same size are skipped, so the
# script is safe to re-run. Nothing is ever deleted. Note: cPanel's nightly
# prune keeps only the configured number of YYYY-MM-DD folders per level
# (daily / weekly / monthly) on the remote, so sets older than the retention
# window will be removed by cPanel on later nights.
#
# Options:
#   --apply          actually upload (default is dry-run)
#   --dest-id ID     destination id (default: the first enabled destination that is not logs-only)
#   --no-system      skip the system/ directory of each set
#   --log FILE       log file (default /root/s3-mirror-<timestamp>.log)

use strict;
use warnings;
use lib '/usr/local/cpanel';
use Getopt::Long;
use POSIX qw(strftime);
use Cpanel::Backup::Transport ();
use Cpanel::Transport::Files  ();

my ($apply, $dest_id, $no_system, $log_file) = (0, '', 0, '');
GetOptions('apply' => \$apply, 'dest-id=s' => \$dest_id, 'no-system' => \$no_system, 'log=s' => \$log_file)
    or die "bad options\n";
my @sets = @ARGV or die "usage: $0 [--apply] [--dest-id ID] [--no-system] SET_DIR...\n";

$log_file ||= strftime("/root/s3-mirror-%Y%m%d-%H%M%S.log", localtime);
open my $LOG, '>>', $log_file or die "cannot open $log_file: $!\n";
$LOG->autoflush(1);
sub logmsg { my $m = strftime("[%Y-%m-%d %H:%M:%S] ", localtime) . join('', @_) . "\n"; print $m; print $LOG $m; }

# --- backup dir from cPanel config ---
my $backup_dir = '/backup';
if (open my $cf, '<', '/var/cpanel/backups/config') {
    while (<$cf>) { $backup_dir = $1 if /^BACKUPDIR:\s*'?([^'\s]+)'?/ }
    close $cf;
}
$backup_dir =~ s{/+$}{};

# --- destination ---
my $bt = Cpanel::Backup::Transport->new();
my $dests = $bt->get_destinations() || {};
if (!$dest_id) {
    for my $id (sort keys %$dests) {
        my $d = $dests->{$id};
        next if $d->{disabled} || $d->{only_used_for_logs};
        $dest_id = $id; last;
    }
}
die "no enabled remote destination found\n" unless $dest_id;
my $cfg = $bt->get($dest_id) or die "destination $dest_id: " . $bt->get_error_msg() . "\n";
my $t   = Cpanel::Transport::Files->new($cfg->{type}, $cfg);
my $base = $t->get_path();
$base =~ s{/+$}{};
logmsg "destination: $cfg->{name} ($cfg->{type}) base=$base  mode=" . ($apply ? "APPLY" : "DRY-RUN") . "  log=$log_file";

sub remote_ls {
    my ($path) = @_;
    my $r = eval { $t->ls($path) };
    return undef if $@ || !$r || !$r->{success};
    return { map { $_->{filename} => $_ } @{ $r->{data} || [] } };
}

sub ensure_dir {
    my ($path) = @_;
    my $ok = eval { $t->ls_check($path); 1 };
    return 1 if $ok;
    logmsg "  mkdir $path";
    return 1 unless $apply;
    eval { $t->mkdir($path); 1 } or do {
        my $e = $@; logmsg "  ERROR mkdir $path: " . (ref $e && $e->can('get_error') ? $e->get_error : "$e"); return 0;
    };
    return 1;
}

my %tot = (files => 0, bytes => 0, skipped => 0, uploaded => 0, failed => 0);
my $t0 = time;

for my $set (@sets) {
    $set =~ s{/+$}{};
    if (!-d $set) { logmsg "SKIP $set: not a directory"; next }
    if ($set !~ m{^\Q$backup_dir\E/((?:weekly/|monthly/)?\d{4}-\d{2}-\d{2})$}) { logmsg "SKIP $set: not a set under $backup_dir"; next }
    my $rel = $1;
    logmsg "SET $set -> $base/$rel";

    my @subdirs = ('accounts');
    push @subdirs, 'system' unless $no_system;
    for my $sub (@subdirs) {
        my $ldir = "$set/$sub";
        next unless -d $ldir;
        opendir my $dh, $ldir or do { logmsg "  ERROR opendir $ldir: $!"; next };
        my @files = sort grep { -f "$ldir/$_" && ($_ eq '.master.meta' || /\.tar(\.gz)?$/) } readdir $dh;
        closedir $dh;
        next unless @files;

        my $rdir = "$base/$rel/$sub";
        ensure_dir("$base/$rel") && ensure_dir($rdir) or next;
        my $existing = remote_ls($rdir) || {};

        for my $f (@files) {
            my $local  = "$ldir/$f";
            my $remote = "$rdir/$f";
            my $size   = -s $local;
            $tot{files}++;
            if (my $e = $existing->{$f}) {
                if (defined $e->{size} && $e->{size} == $size) { $tot{skipped}++; next }
                logmsg sprintf("  REPLACE %s (remote %s bytes, local %s)", $f, $e->{size} // '?', $size);
            }
            $tot{bytes} += $size;
            logmsg sprintf("  %s %s (%.1fM) -> %s", $apply ? "PUT" : "would put", $f, $size / 2**20, $remote);
            next unless $apply;

            my $done = 0;
            for my $try (1 .. 3) {
                my $t1 = time;
                if (eval { $t->put($local, $remote); 1 }) {
                    my $dt = (time - $t1) || 1;
                    logmsg sprintf("    ok in %ds (%.1f MB/s)", $dt, $size / 2**20 / $dt);
                    $done = 1; last;
                }
                my $e = $@;
                logmsg "    attempt $try failed: " . (ref $e && $e->can('get_error') ? $e->get_error : "$e");
                sleep 10 * $try;
            }
            if ($done) { $tot{uploaded}++ } else { $tot{failed}++ }
        }
    }
}

logmsg sprintf("DONE files=%d skipped=%d %s=%d failed=%d bytes=%.1fG elapsed=%dm",
    $tot{files}, $tot{skipped}, ($apply ? "uploaded" : "to-upload"), ($apply ? $tot{uploaded} : $tot{files} - $tot{skipped}),
    $tot{failed}, $tot{bytes} / 2**30, (time - $t0) / 60);
exit($tot{failed} ? 1 : 0);
