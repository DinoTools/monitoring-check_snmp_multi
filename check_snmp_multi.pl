#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use Net::SNMP;
use Pod::Text::Termcap;

use constant OK         => 0;
use constant WARNING    => 1;
use constant CRITICAL   => 2;
use constant UNKNOWN    => 3;
use constant DEPENDENT  => 4;

my $pkg_nagios_available = 0;
my $pkg_monitoring_available = 0;
my @g_long_message;

BEGIN {
    eval {
        require Monitoring::Plugin;
        require Monitoring::Plugin::Functions;
        $pkg_monitoring_available = 1;
    };
    if (!$pkg_monitoring_available) {
        eval {
            require Nagios::Plugin;
            require Nagios::Plugin::Functions;
            *Monitoring::Plugin:: = *Nagios::Plugin::;
            $pkg_nagios_available = 1;
        };
    }
    if (!$pkg_monitoring_available && !$pkg_nagios_available) {
        print("UNKNOWN - Unable to find module Monitoring::Plugin or Nagios::Plugin\n");
        exit UNKNOWN;
    }
}

my $parser = Pod::Text::Termcap->new (sentence => 0, width => 78);
my $extra_doc = <<'END_MESSAGE';

=head1 Examples

Get two strings with custom OID

=head2 Example 1

B<Command>:

./check_snmp_multi.pl -C community -H hostname --value="Get String=string:.1.2.3" --value="Get 2nd string=string:.1.2.4"

B<Output>:

check_snmp_multi OK - Get String: Test Get 2nd string: Test 2

=cut

=head2 Example 2

B<Command>:

./check_snmp_multi.pl -C community -H hostname --loop_start=1 --loop_stop=2 --loop_value="Version=string:.1.2.3.\$id" --loop_value="Hardware=string:.1.2.4.\$id"

B<Output>:

check_snmp_multi OK

Loop: 1

=======

  * Version: 1.0
  * Hardware: 0031

Loop: 2

=======

  * Version: 1.0
  * Hardware: 0199
=cut

END_MESSAGE

my $extra_doc_output;
$parser->output_string(\$extra_doc_output);
$parser->parse_string_document($extra_doc);

my $mp = Monitoring::Plugin->new(
    shortname => "check_snmp_multi",
    usage => "",
    extra => $extra_doc_output
);

$mp->add_arg(
    spec    => 'community|C=s',
    help    => 'Community string (Default: public)',
    default => 'public'
);

$mp->add_arg(
    spec => 'hostname|H=s',
    help => '',
    required => 1
);

$mp->add_arg(
    spec    => 'base:s',
    help    => 'Base oid',
    default => '1.3.6.1.4.1.34796',
);

$mp->add_arg(
    spec    => 'value=s@',
    help    => 'Values to monitor',
    default => []
);

$mp->add_arg(
    spec    => 'loop_start=i',
    help    => '',
    default => undef,
);

$mp->add_arg(
    spec    => 'loop_stop=i',
    help    => '',
    default => undef,
);

$mp->add_arg(
    spec    => 'loop_value=s@',
    help    => 'Values to monitor',
    default => []
);

$mp->getopts;

#Open SNMP Session
my ($session, $error) = Net::SNMP->session(
    -hostname => $mp->opts->hostname,
    -version => 'snmpv2c',
    -community => $mp->opts->community,
);

if (!defined($session)) {
    wrap_exit(UNKNOWN, $error)
}

check();

my ($code, $message) = $mp->check_messages();
wrap_exit($code, $message . "\n" . join("\n", @g_long_message));

sub build_oid
{
    my ($base_oid, $oid, $loop_value) = @_;
    # Remove white space
    $oid =~ s/^\s+//;
    # Use oid if it starts with .
    if ($oid =~ /^\./) {
      $oid =~ s/^(\s|\.)+//;
      return build_oid_loop($oid, $loop_value);
    }
    $base_oid =~ s/(\s|[.])+$//;
    return build_oid_loop($base_oid . '.' . $oid, $loop_value);
}

sub build_oid_loop
{
    my ($oid, $loop_value) = @_;
    if (defined $loop_value) {
      $oid =~ s/\$id/$loop_value/;
    }
    return $oid;
}

sub check
{
    my @values;
    my @loop_values;

    foreach my $value (@{$mp->opts->value}) {
        my $value_cfg = parse_value_config($value);
        push @values, $value_cfg;
    }
    check_status(\@values);


    if(defined $mp->opts->loop_start && defined $mp->opts->loop_stop) {
        foreach my $value (@{$mp->opts->loop_value}) {
            my $value_cfg = parse_value_config($value);
            push @loop_values, $value_cfg;
        }
        for(my $i=$mp->opts->loop_start; $i <= $mp->opts->loop_stop; $i++) {
            if ($i > $mp->opts->loop_start) {
                push @g_long_message, '';
            }
            push @g_long_message, sprintf("Loop: %d", $i);
            push @g_long_message, "=======";
            push @g_long_message, '';
            check_status(\@loop_values, $i);
        }
    }
}

sub check_status
{
    my ($values_ref, $loop_value) = @_;
    my @values = @{$values_ref};

    my $request_values = [];
    my $result;

#    for ($i=0; $i < scalar(@values); $i++) {
#        my %value_cfg = %{$values[$i]};
#        push $request_values, '1.3.6.1.4.1.34796.' . $value_cfg{oid};
#    }
#    $result = $session->get_request(
#        -varbindlist => $request_values
#    );
    my $base_oid = $mp->opts->base;
    for (my $i=0; $i < scalar(@values); $i++) {
        my %value_cfg = %{$values[$i]};
        my $oid = build_oid($base_oid, $value_cfg{oid}, $loop_value);
        $result = $session->get_request(
            -varbindlist => [$oid]
        );
        my $value = $result->{$oid};
        my $value_type = $value_cfg{type};
        if ($value_type =~ m/^bool/) {
            check_status_bool(\%value_cfg, $value, $loop_value);
        } elsif ($value_type =~ m/^float/) {
            check_status_float(\%value_cfg, $value, $loop_value);
        } elsif ($value_type =~ m/^str/) {
            check_status_string(\%value_cfg, $value, $loop_value);
        }
    }
#    foreach my $value_cfg (@values) {
#        my $value = $result->{'.1.3.6.1.4.1.34796.' . $oid};
#        my $value_type = $values{$oid}{type};
#        if ($value_type eq 'bool') {
#            check_status_bool($values{$oid}, $value);
#        }
#
#    }

}

sub check_status_bool
{
    my ($f, $value, $loop_value) = @_;
    my %value_cfg = %{$f};
    my ($type_name, $text_false, $text_true) = split /,/, $value_cfg{type};

    my $check_status = OK;
    if (defined $value_cfg{threshold_warning} && $value_cfg{threshold_warning} == $value) {
        $check_status = WARNING;
    } elsif (defined $value_cfg{threshold_critical} && $value_cfg{threshold_critical} == $value) {
        $check_status = CRITICAL;
    }
    $mp->add_perfdata(
        label     => $value_cfg{label},
        value     => $value,
    );
    my $msg = $value;
    if (defined $text_false && $value == 0) {
      $msg = $text_false . "($value)";
    } elsif (defined $text_true && $value == 1) {
      $msg = $text_true . "($value)";
    }
    $mp->add_message($check_status, $value_cfg{label} . ': ' . $msg);
}

sub check_status_float
{
    my $check_status;

    my ($f, $value, $loop_value) = @_;
    my %value_cfg = %{$f};
    my ($type_name, $type_modifier, $type_mod_value) = split /,/, $value_cfg{type};
    if (defined $type_modifier && defined $type_mod_value) {
        if ($type_modifier eq '/') {
            $value /= $type_mod_value;
        } elsif ($type_modifier eq '*') {
            $value *= $type_mod_value;
        }
    }

    $mp->add_perfdata(
        label     => $value_cfg{label},
        value     => $value,
        warning   => $value_cfg{threshold_warning},
        critical  => $value_cfg{threshold_critical},
        uom       => $value_cfg{uom},
    );
    $check_status = $mp->check_threshold(
        check     => $value,
        warning   => $value_cfg{threshold_warning},
        critical  => $value_cfg{threshold_critical},
    );
    $mp->add_message($check_status, $value_cfg{label} . ': ' .  $value . ($value_cfg{label_uom} // ""));
}

sub check_status_string
{
    my $check_status;

    my ($f, $value, $loop_value) = @_;
    my %value_cfg = %{$f};
    wrap_add_message(OK, $value_cfg{label} . ': ' .  $value . ($value_cfg{label_uom} // ""), $loop_value);
}

sub parse_value_config
{
    my $value = shift;
    my $label;
    my $label_uom;
    my $uom;
    my $type;
    my $i;

    ($label, $value) = split /=/, $value, 2;
    ($label, $label_uom, $uom) = split /;/, $label, 3;

    my ($oid_value, $threshold) = split /;/, $value;
    my ($oid_type, $oid) = split /:/, $oid_value;
    if (!defined $oid) {
        $oid = $oid_type;
        $oid_type = 'int';
    }
    my ($threshold_warning, $threshold_critical);
    if (defined $threshold) {
        ($threshold_warning, $threshold_critical) = split /,/, $threshold;
        if (defined $threshold_warning && $threshold_warning eq "") {
            undef $threshold_warning;
        }
        if (defined $threshold_critical && $threshold_critical eq "") {
            undef $threshold_critical;
        }
    }

    my %foo = (
        'label'              => $label,
        'label_uom'          => $label_uom,
        'uom'                => $uom,
        'oid'                => $oid,
        'threshold_warning'  => $threshold_warning,
        'threshold_critical' => $threshold_critical,
        'type'               => $oid_type,
    );
    return \%foo;
}

sub wrap_add_message
{
    my ($check_status, $message, $loop_value) = @_;
    if (defined $loop_value) {
        push @g_long_message, '  * ' . $message;
    }
    if (!defined $loop_value || $check_status != OK) {
        $mp->add_message($check_status, $message);
    }
}

sub wrap_exit
{
    if($pkg_monitoring_available == 1) {
        $mp->plugin_exit( @_ );
    } else {
        $mp->nagios_exit( @_ );
    }
}
