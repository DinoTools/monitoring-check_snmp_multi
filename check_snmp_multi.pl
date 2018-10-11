#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use Class::Load qw(try_load_class is_class_loaded);

use Net::SNMP;

use constant OK         => 0;
use constant WARNING    => 1;
use constant CRITICAL   => 2;
use constant UNKNOWN    => 3;
use constant DEPENDENT  => 4;

my $pkg_nagios_available = 0;
my $pkg_monitoring_available = 0;

BEGIN {
    $pkg_nagios_available = try_load_class('Nagios::Plugin');
    $pkg_monitoring_available = try_load_class('Monitoring::Plugin');
    if($pkg_monitoring_available == 1) {
        require Monitoring::Plugin;
        require Monitoring::Plugin::Functions;
        require Monitoring::Plugin::Threshold;
    } elsif ($pkg_nagios_available == 1) {
        require Nagios::Plugin;
        require Nagios::Plugin::Functions;
        require Nagios::Plugin::Threshold;
        *Monitoring::Plugin:: = *Nagios::Plugin::;
    }
}

my $mp = Monitoring::Plugin->new(
    shortname => "check_snmp_multi",
    usage => ""
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
    spec    => 'value=s@',
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

check_status();

my ($code, $message) = $mp->check_messages();
wrap_exit($code, $message);

sub check_status
{
    my $label;
    my $uom;
    my $type;
    my $i;
    my @values;
    foreach my $value (@{$mp->opts->value}) {
        ($label, $value) = split /=/, $value, 2;
        ($label, $uom) = split /;/, $label, 2;

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
            'uom'                => $uom,
            'oid'                => $oid,
            'threshold_warning'  => $threshold_warning,
            'threshold_critical' => $threshold_critical,
            'type'               => $oid_type,
        );

        push @values, \%foo;

    }

    my $request_values = [];
    my $result;

#    for ($i=0; $i < scalar(@values); $i++) {
#        my %value_cfg = %{$values[$i]};
#        push $request_values, '1.3.6.1.4.1.34796.' . $value_cfg{oid};
#    }
#    $result = $session->get_request(
#        -varbindlist => $request_values
#    );
    for ($i=0; $i < scalar(@values); $i++) {
        my %value_cfg = %{$values[$i]};
        $result = $session->get_request(
            -varbindlist => ['1.3.6.1.4.1.34796.' . $value_cfg{oid}]
        );
        my $value = $result->{'1.3.6.1.4.1.34796.' . $value_cfg{oid}};
        my $value_type = $value_cfg{type};
        if ($value_type eq 'bool') {
            check_status_bool(\%value_cfg, $value);
        } elsif ($value_type =~ m/^float/) {
            check_status_float(\%value_cfg, $value);
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
    my $f = shift;
    my %value_cfg = %{$f};
    my $value = shift;
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
    $mp->add_message($check_status, $value_cfg{label} . ': ' .  $value);
}

sub check_status_float
{
    my $check_status;

    my $f = shift;
    my %value_cfg = %{$f};
    my $value = shift;
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
    $mp->add_message($check_status, $value_cfg{label} . ': ' .  $value . ($value_cfg{uom} // ""));
}

sub wrap_exit
{
    if($pkg_monitoring_available == 1) {
        $mp->plugin_exit( @_ );
    } else {
        $mp->nagios_exit( @_ );
    }
}
