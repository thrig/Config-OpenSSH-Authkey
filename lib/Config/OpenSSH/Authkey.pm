package Config::OpenSSH::Authkey;

require 5.006;

use warnings;
use strict;

use Carp qw(croak);
use Config::OpenSSH::Authkey::Entry ();

our $VERSION = '0.01';

# TODO OpenSSH only consults the first public key seen in a file.
# Duplicates, therefore, should be dropped (and if necessary alerted
# about). However, entries with bad options will be thrown out, so dups
# must be for "valid" key entries...
my %seen_keys;

sub new {
  my $class = shift;
  my $self  = {};
  bless $self, $class;
  return $self;
}

sub parse_file {
  my ( $self, $file ) = @_;

  my $fh;
  open( $fh, '<', $file ) or croak($!);
  parse_fh( $self, $fh );
}

sub parse_fh {
  my ( $self, $fh ) = @_;

  while ( my $line = <$fh> ) {
    # TODO want support to preserve blank lines, comments, order of
    # public keys in the input data. I'm thinking callbacks to the user.
    if ( $line =~ m/^\s*$/ ) {
      warn "skipping blank line at line $.\n";
      next;
    }
    if ( $line =~ m/^\s*#/ ) {
      warn "skipping commented line at line $.\n";
      next;
    }

    eval {
      my $entry = Config::OpenSSH::Authkey::Entry->new($line);

      my $key = $entry->key;
      if ( exists $seen_keys{$key} ) {
        warn "duplicate key at line $.\n";
      }

      push @{ $self->{_keys} }, $entry;
      push @{ $seen_keys{$key} }, $#{ $self->{_keys} };
    };
    if ($@) {
      chomp $@;
      # TODO options to leave alone, or disable unparseable entries
      warn "skipping unparseable entry at line $.: $@\n";
    }
  }

  return $self;
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
