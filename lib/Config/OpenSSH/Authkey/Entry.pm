# Representation of individual OpenSSH authorized_keys entries.

package Config::OpenSSH::Authkey::Entry;

use warnings;
use strict;

use Carp qw(croak);

our $VERSION = '0.01';

# Delved from sshd(8). TODO Need to confirm against latest OpenSSH
# release. (And perhaps maintain a list of supported option by OpenSSH
# version, if they've added any...)
#
# TODO need methods to return these, e.g. so test scripts can exercise
# full range of options...
my %AK_OPTS_ARGV = qw{from 1 command 1 environment 1 permitopen 1};
my $AK_OPTS_ARGV_RE = join( '|', keys %AK_OPTS_ARGV );

my %AK_OPTS_BOOL =
  qw{no-port-forwarding 1 no-X11-forwarding 1 no-agent-forwarding 1 no-pty 1};
my $AK_OPTS_BOOL_RE = join( '|', keys %AK_OPTS_BOOL );

######################################################################
#
# Class methods

sub get_options {
  my $class = shift;
  my $type  = shift;
  my @options;

  if ( $type eq 'boolean' ) {
    @options = sort keys %AK_OPTS_BOOL;
  } elsif ( $type eq 'argument' ) {
    @options = sort keys %AK_OPTS_ARGV;
  } else {
    @options = sort ( keys %AK_OPTS_ARGV, keys %AK_OPTS_BOOL );
  }

  return @options;
}

######################################################################
#
# Instance methods

sub new {
  my $class = shift;
  my $self  = {};

  my $auth_key_string = shift or croak('authorized_keys line not supplied');

  if ( exists $self->{_source} ) {
    croak('instance already initialized');
  }

  $self->{_source} = $auth_key_string;
  _parse_ak_entry( $self, $auth_key_string );

  bless $self, $class;
  return $self;
}

sub as_string {
  my $self   = shift;
  my $string = q{};

  if ( !exists $self->{_is_changed} ) {
    $string = $self->{_source};

  } elsif ( exists $self->{_as_string} ) {
    $string = $self->{_as_string};

  } else {
    if ( exists $self->{_opt_order} and @{ $self->{_opt_order} } ) {
      $string = join( ',',
        _listify_options( $self->{_opt_order}, $self->{_options} ) );
      if ( length $string > 0 ) {
        $string .= q{ };
      }
    }

    $string .= $self->{_key};
    if ( exists $self->{_comment} and length $self->{_comment} > 0 ) {
      $string .= q{ } . $self->{_comment};
    }

    $self->{_as_string} = $string;
  }

  return $string;
}

######################################################################
#
# Utility methods - not for use outside this module!

sub _listify_options {
  my $order_ref   = shift;
  my $options_ref = shift;
  my @options;

  for my $option_name (@$order_ref) {
    if ( exists $options_ref->{$option_name} ) {
      if ( defined $options_ref->{$option_name} ) {
        push @options,
          $option_name . '="' . $options_ref->{$option_name} . '"';
      } else {
        push @options, $option_name;
      }
    }
  }

  return @options;
}

sub _parse_ak_entry {
  my $self  = shift;
  my $entry = shift;

  chomp $entry;

  # Lex-like parser for authorzied_keys entries
UBLE: {
    # NOTE that 512 bit RSA1 keys are not supported. 1000 to 99999 bit
    # keypairs should suffice for near future, considering SSH1 should
    # have been taken out and shot years ago. But I digress.
    if (
      $entry =~ m/ \G (\d{4,5} \s+? \d+ \s+? \d+    # rsa1 keys
        |ssh-(?:rsa|ds[as])\s+?[A-Za-z0-9+\/]+=*)  # Protocol 2 key types
        \s* /cgx
      ) {

      $self->{_key} = $1;

      # Optional trailing comment
      if ( $entry =~ m/ \G (.+) /cgx ) {
        $self->{_comment} = $1;
      }

      last UBLE;
    }

    # Options with arguments
    if (
      $entry =~ m/ \G ($AK_OPTS_ARGV_RE)="( \\.|[^\\"] )+" (?:,|\s+)? /cgx ) {
      # TODO how if at all does OpenSSL handle duplicated options that
      # accept arguments?
      $self->{_options}->{$1} = $2;
      push @{ $self->{_opt_order} }, $1;

      redo UBLE;
    }

    # Boolean options
    if ( $entry =~ m/ \G ($AK_OPTS_BOOL_RE) (?:,|\s+)? /cgx ) {
      $self->{_options}->{$1} = undef;
      push @{ $self->{_opt_order} }, $1;

      redo UBLE;
    }
  }

  # TODO return false if unable to parse? Or handle that elsewhere?
  return 1;
}

1;

__END__

=head1 NAME

Config::OpenSSH::Authkey::Entry - authorized_keys file entry

=head1 SYNOPSIS

  TODO

=head1 DESCRIPTION

TODO

=head1 METHODS

TODO

=head1 BUGS

No known bugs.
  
=head2 Reporting Bugs
  
Newer versions of this module may be available from CPAN.
  
If the bug is in the latest version, send a report to the author.
Patches that fix problems or add new features are welcome.

=head2 Known Issues

No known issues.

=head1 SEE ALSO

sshd(8), L<Config::OpenSSH::Authkey|Config::OpenSSH::Authkey>

=head1 AUTHOR

Jeremy Mates, E<lt>jmates@sial.orgE<gt>

=head1 COPYRIGHT

Copyright 2009 by Jeremy Mates.

This program is free software; you can redistribute it and/or modify it
under the Artistic license.

=cut
