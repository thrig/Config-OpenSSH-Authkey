# -*- Perl -*-
#
# Representation of individual OpenSSH authorized_keys entries. Based on
# a study of the sshd(8) manual, along with the OpenSSH 5.2 sources.

package Config::OpenSSH::Authkey::Entry;

use warnings;
use strict;

use Carp qw(croak);

our $VERSION = '0.01';

# This limit is set for various things under OpenSSH code. Used here to
# limit length of authorized_keys lines.
my $SSH_MAX_PUBKEY_BYTES = 8192;

sub new {
  my $class = shift;
  my $self  = {};
  my $entry = shift || q{};

  my ( $options, $key, $comment, $protocol );

  chomp $entry;

  if ( $entry =~ m/^\s*$/ or $entry =~ m/^\s*#/ ) {
    croak('no public key data');
  } elsif ( length $entry >= $SSH_MAX_PUBKEY_BYTES ) {
    croak('exceeds size limit');
  }

  # OpenSSH supports leading whitespace before options or key. Strip
  # this optional whitespace to simplify parsing.
  $entry =~ s/^[ \t]+//;

  # Lex-like parser for authorzied_keys entries
UBLE: {
    # Optional trailing comment
    if ( defined $key and $entry =~ m/ \G (.+) /cgx ) {
      $comment = $1;

      last UBLE;
    }

    # SSH2 RSA or DSA public key
    if ( !defined $key
      and $entry =~
      m/ \G ( ssh-(?:rsa|dss) [ \t]+? [A-Za-z0-9+\/]+ =* ) [ \t]* /cgx ) {

      $key      = $1;
      $protocol = 2;

      redo UBLE;
    }

    # SSH1 RSA public key
    if ( !defined $key
      and $entry =~ m/ \G ( \d{3,5} [ \t]+? \d+ [ \t]+? \d+ ) [ \t]* /cgx ) {

      $key      = $1;
      $protocol = 1;

      redo UBLE;
    }

    # Optional leading options - may contain whitespace inside ""
    if ( !defined $key and $entry =~ m/ \G ([^ \t]+? [ \t]*) /cgx ) {
      $options .= $1;

      redo UBLE;
    }
  }

  if ( !defined $key ) {
    croak('unable to parse public key');

  } else {
    if ( defined $options ) {
      $options =~ s/\s*$//;
      $self->{_options} = $options;
    }
    $self->{_key}      = $key;
    $self->{_protocol} = $protocol;
    if ( defined $comment ) {
      $comment =~ s/\s*$//;
      $self->{_comment} = $comment;
    }
  }

  bless $self, $class;
  return $self;
}

######################################################################
#
# Instance methods

sub key {
  shift->{_key};
}

sub protocol {
  shift->{_protocol};
}

sub comment {
  my $self    = shift;
  my $comment = shift;
  if ( defined $comment ) {
    $self->{_comment} = $comment;
  }
  return $self->{_comment};
}

# TODO also support submodule that provides a programmatic interface to
# these? E.g. if ->can, pull as_string from it in turn.
sub options {
  my $self    = shift;
  my $options = shift;
  if ( defined $options ) {
    $self->{_options} = $options;
  }
  return $self->{_options};
}

sub as_string {
  my $self   = shift;
  my $string = q{};

  if ( exists $self->{_options} and length $self->{_options} > 0 ) {
    $string .= $self->{_options} . q{ };
  }
  $string .= $self->{_key};
  if ( exists $self->{_comment} and length $self->{_comment} > 0 ) {
    $string .= q{ } . $self->{_comment};
  }

  return $string;
}

1;

__DATA__

TODO for the option parsing code... this should probably live in a
different package.

# Delved from sshd(8), auth-options.c of OpenSSH 5.2. Insensitive match
# required, as OpenSSH uses strncasecmp(3).
my %AK_OPTS_ARGV = qw{from 1 command 1 environment 1 permitopen 1 tunnel 1};
my $AK_OPTS_ARGV_RE = '(?i)' . join( '|', keys %AK_OPTS_ARGV );

# from auth-options.c
my %AK_OPTS_BOOL =
  qw{no-port-forwarding 1 no-agent-forwarding 1 no-X11-forwarding 1 no-pty 1 no-user-rc 1};
my $AK_OPTS_BOOL_RE = '(?i)' . join( '|', keys %AK_OPTS_BOOL );

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



    # Inspected OpenSSH auth-options.c,v 1.44 to derive this regex:
    # looking for a perhaps empty string enclosed in doublequotes, which
    # allows internal doublequotes, but only if these are preceeded by a
    # backslash.
    #
    # NOTE Junk options call bad_options and reject the line. Hence the
    # parsing of options now, instead of deferring that parsing to only
    # when the options change. Risk is failing on new options added into
    # new versions of OpenSSH.
    if (
      $entry =~ m/ \G ($AK_OPTS_ARGV_RE)="( (?: \\"|[^"] )+? )"
        (?:,|[ \t]+)? /cgx
      ) {
      # OpenSSH_5.1p1 and options command="echo one",command="echo two"
      # shows a response of "two". However, multiple from="" causes
      # logins to fail, if there is one bad entry, regardless of order,
      # and entry to pass if all the from="" otherwise permit the
      # connection. :/
      #
      # command - last defined wins
      # environment - one env per environment="", first set wins
      # from - TODO
      #
      # TODO also need instance and global defaults for "mess not with
      # options" so can support use-cases where folks don't want the
      # options played with.
      #
      # Also must set is_changed if mess with the options here!
      #
      # So really must go inspect the OpenSSH source code to learn how
      # to handle these options...
      $self->{_options}->{$1} = $2;
      push @{ $self->{_opt_order} }, $1;

      redo UBLE;
    }

    # Boolean options
    if ( $entry =~ m/ \G ($AK_OPTS_BOOL_RE) (?:,|[ \t]+)? /cgx ) {
      $self->{_options}->{$1} = undef;
      push @{ $self->{_opt_order} }, $1;

      redo UBLE;
    }

__END__

=head1 NAME

Config::OpenSSH::Authkey::Entry - authorized_keys file entry

=head1 SYNOPSIS

  TODO

=head1 DESCRIPTION

This module parses input OpenSSH authorized_keys lines.

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
