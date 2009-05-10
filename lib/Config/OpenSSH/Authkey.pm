package Config::OpenSSH::Authkey;

require 5.006;

use warnings;
use strict;

our $VERSION = '0.01';

sub new {
  my $class = shift;
  my $self  = {};
  bless $self, $class;
  return $self;
}

# TODO parse_fh, parse_file methods?

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
