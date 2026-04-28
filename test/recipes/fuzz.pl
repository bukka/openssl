# Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use Cwd qw/abs_path/;

use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT srctop_dir bldtop_file result_file/;

sub fuzz_check_log {
    my ($f, $log, $exit_ok) = @_;

    my $has_leaks = 0;
    my @tail;
    my ($last_path, $last_point);

    if (open(my $fh, '<', $log)) {
        while (my $line = <$fh>) {
            chomp $line;
            if ($line =~ /^#\s/) {
                $last_path  = $1 if $line =~ /\bpath=(.+?)\s*$/;
                $last_point = $1 if $line =~ /\bpoint=(\d+)\//;
                @tail = ($line);
            } else {
                push @tail, $line;
                $has_leaks = 1
                    if $line =~ /^(?:Direct|Indirect) leak of \d+ byte/;
            }
        }
        close $fh;
    }

    return 1 if $exit_ok && !$has_leaks;

    my $why = !$exit_ok ? "non-zero exit" : "leaks (clean exit)";
    diag("fuzz $f failed: $why");
    diag("- full stderr: $log");
    if (defined $last_path) {
        my $bin  = abs_path(bldtop_file('fuzz', "$f-test"));
        my $path = abs_path($last_path);
        my $env  = defined $last_point
            ? "OPENSSL_TEST_MFAIL_POINT=$last_point " : "";
        diag("- reproduce: $env$bin $path");
    }
    diag($_) for @tail;
    return 0;
}

sub fuzz_ok {
    my ($f, %opts) = @_;
    my $d = srctop_dir('fuzz', 'corpora', $f);

    SKIP: {
        skip "No directory $d", 1 unless -d $d;

        my $budget = $ENV{OSSL_FUZZ_TEST_BUDGET};
        my $jobs   = $ENV{OSSL_FUZZ_TEST_JOBS} || 1;

        if (!$budget) {
            ok(run(fuzz(["$f-test", $d])), "Fuzzing $f");
            return;
        }

        my @fuzz_dirs = grep { -d }
            glob(srctop_dir('fuzz', 'corpora') . '/*');
        my $per_test = $budget * $jobs / scalar(@fuzz_dirs);

        my $base_log = result_file("$f-baseline.stderr.log");
        my $base_ok;
        my @out;
        if ($ENV{HARNESS_VERBOSE}) {
            @out = run(fuzz(["$f-test", $d]),
                       capture => 1, statusvar => \$base_ok);
        } else {
            @out = run(fuzz(["$f-test", $d], stderr => $base_log),
                       capture => 1, statusvar => \$base_ok);
            $base_ok = fuzz_check_log($f, $base_log, $base_ok);
        }
        print @out;

        unless ($base_ok) {
            ok(0, "Fuzzing $f (baseline)");
            return;
        }

        my $corpus_time = 0;
        for my $line (@out) {
            $corpus_time = $1 if $line =~ /^#\s*corpus_time:\s*([\d.]+)/;
        }

        if ($corpus_time <= 0 || $corpus_time >= $per_test) {
            ok(1, "Fuzzing $f (no mfail budget)");
            return;
        }

        my $count = int($per_test / $corpus_time - 1);
        if ($count <= 0) {
            ok(1, "Fuzzing $f (budget too small for mfail)");
            return;
        }

        local $ENV{OPENSSL_TEST_MFAIL_COUNT} = $count;
        my $log = result_file("$f-mfail.stderr.log");

        my $passed;
        if ($ENV{HARNESS_VERBOSE}) {
            $passed = run(fuzz(["$f-test", $d]));
        } else {
            my $exit_ok = run(fuzz(["$f-test", $d], stderr => $log));
            $passed = fuzz_check_log($f, $log, $exit_ok);
        }
        ok($passed, "Fuzzing $f (mfail count=$count, budget ${per_test}s)");
    }
}

1;
