# -*- Perl -*-

package Config::OpenSSH::Authkey;

require 5.006;

use warnings;
use strict;

use Carp qw(croak);
use Config::OpenSSH::Authkey::Entry ();

our $VERSION = '0.01';

# For (optional) duplicate suppression
my %seen_keys;

sub new {
  my $class = shift;
  my $self  = {};
  bless $self, $class;
  return $self;
}

sub parse_file {
  my $self = shift;
  my $file = shift;

  my $fh;
  open( $fh, '<', $file ) or croak($!);

  $self->parse_fh( $fh, @_ );
}

sub parse_fh {
  my ( $self, $fh, $callback_ref, $kill_dups ) = @_;

  if ( defined $callback_ref ) {
    croak('callback not a CODE reference') unless ref $callback_ref eq 'CODE';
  } else {
    $callback_ref = sub { shift eq 'pubkey' ? 1 : 0 };
  }
  $kill_dups = 0 if !defined $kill_dups;

  while ( my $line = <$fh> ) {
    if ( $line =~ m/^\s*(?:#|$)/ ) {
      $callback_ref->( 'metadata', $line );
    } else {
      eval {
        my $entry = Config::OpenSSH::Authkey::Entry->new($line);

        if ($kill_dups) {
          next if $seen_keys{ $entry->key }++;
        }

        if ( $callback_ref->( 'pubkey', $line, $@ ) ) {
          push @{ $self->{_keys} }, $entry;
        }
      };
      if ($@) {
        $callback_ref->( 'unknown', $line, $@ );
      }
    }
  }

  return $self;
}

sub keys {
  shift->{_keys};
}

1;

__END__

=head1 NAME

Config::OpenSSH::Authkey - interface to OpenSSH authorized_keys

=head1 SYNOPSIS

  use Config::OpenSSH::Authkey ();

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

sshd(8), L<Config::OpenSSH::Authkey::Entry|Config::OpenSSH::Authkey::Entry>

=head1 AUTHOR

Jeremy Mates, E<lt>jmates@sial.orgE<gt>

=head1 COPYRIGHT

Copyright 2009 by Jeremy Mates.

This program is free software; you can redistribute it and/or modify it
under the Artistic license.

=cut
