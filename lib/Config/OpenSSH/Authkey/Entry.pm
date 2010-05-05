# -*- Perl -*-
#
# Representation of individual OpenSSH authorized_keys entries, based on
# a study of the sshd(8) manual, along with the OpenSSH 5.2 sources.
# This module only weakly validates the data presented; in particular,
# no effort is made to confirm whether the key options are actual valid
# options for the version of OpenSSH in question.

package Config::OpenSSH::Authkey::Entry;

use strict;
use warnings;

use Carp qw(croak);

our $VERSION = '0.02';

# This limit is set for various things under OpenSSH code. Used here to
# limit length of authorized_keys lines.
my $MAX_PUBKEY_BYTES = 8192;

# Delved from sshd(8), auth-options.c of OpenSSH 5.2. Insensitive match
# required, as OpenSSH uses strncasecmp(3).
my $AUTHKEY_OPTION_NAME_RE = qr/(?i)[a-z0-9_-]+/;

######################################################################
#
# Data Parsing Methods - Internal

my $_split_options = sub {
  my $self    = shift;
  my $options = shift;

  # Inspected OpenSSH auth-options.c,v 1.44 to derive this lexer:
  #
  # * In OpenSSH, unparsable options result in a call to bad_options and
  #   the entry being rejected. This module is more permissive, in that
  #   any option name (any boolean state or any string value) will be
  #   parsed, regardless of whether OpenSSH supports such an option or
  #   the type of the option.
  #
  # TODO need to delve more into how OpenSSH handles the various
  # arguments that pass options (e.g. if multiple from="" or etc. exist
  # in file). Might just throw an error if anything odd found, and let
  # caller sort things out for the rare(?) bogus entry.

OPTION_LEXER: {
    # String Argument Options - value is a perhaps empty string enclosed
    # in doublequotes. Internal doublequotes are allowed, but only if
    # these are preceeded by a backslash.
    if (
      $options =~ m/ \G ($AUTHKEY_OPTION_NAME_RE)="( (?: \\"|[^"] )+? )"
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

      redo OPTION_LEXER;
    }

    # Boolean options - mere presence enables them in OpenSSH
    if ( $options =~ m/ \G ($AUTHKEY_OPTION_NAME_RE) (?:,|[ \t]+)? /cgx ) {

      # TODO - want means to also preserve option order from input to
      # output (ideally via a code ref, so folks can use a custom sort,
      # if desired?

      redo OPTION_LEXER;
    }
  }

  return 'TODO';
};

my $_parse_entry = sub {
  my $self  = shift;
  my $entry = shift || q{};
  my $prefs = shift || {};

  my ( $options, $key, $comment, $protocol );

  chomp $entry;

  if ( $entry =~ m/^\s*$/ or $entry =~ m/^\s*#/ ) {
    return ( 0, 'no public key data' );
  } elsif ( length $entry >= $MAX_PUBKEY_BYTES ) {
    return ( 0, 'exceeds size limit' );
  }

  # OpenSSH supports leading whitespace before options or key. Strip
  # this optional whitespace to simplify parsing.
  $entry =~ s/^[ \t]+//;

ENTRY_LEXER: {
    # Optional trailing comment
    if ( defined $key and $entry =~ m/ \G (.+) /cgx ) {
      $comment = $1;

      last ENTRY_LEXER;
    }

    # SSH2 RSA or DSA public key
    if ( !defined $key
      and $entry =~
      m/ \G ( ssh-(?:rsa|dss) [ \t]+? [A-Za-z0-9+\/]+ =* ) [ \t]* /cgx ) {

      $key      = $1;
      $protocol = 2;

      redo ENTRY_LEXER;
    }

    # SSH1 RSA public key
    if ( !defined $key
      and $entry =~ m/ \G ( \d{3,5} [ \t]+? \d+ [ \t]+? \d+ ) [ \t]* /cgx ) {

      $key      = $1;
      $protocol = 1;

      redo ENTRY_LEXER;
    }

    # Optional leading options - may contain whitespace inside ""
    if ( !defined $key and $entry =~ m/ \G ([^ \t]+? [ \t]*) /cgx ) {
      $options .= $1;

      redo ENTRY_LEXER;
    }
  }

  if ( !defined $key ) {
    return ( 0, 'unable to parse public key' );

  } else {
    $self->{_key}      = $key;
    $self->{_protocol} = $protocol;

    if ( defined $options ) {
      $options =~ s/\s*$//;
      $self->{_options} = $options;

      if (  exists $prefs->{parse_options}
        and $prefs->{parse_options}
        and length $options > 0 ) {
        my ( $is_parsed, $err_msg ) = $_split_options->( $self, $options );
        if ( !$is_parsed ) {
          return ( 0, $err_msg );
        }
      }
    }

    if ( defined $comment ) {
      $comment =~ s/\s*$//;
      $self->{_comment} = $comment;
    }
  }

  return ( 1, 'ok' );
};

######################################################################
#
# Class methods

sub new {
  my $class = shift;
  my $entry = shift;
  my $prefs = shift || {};

  my $self = {};

  if ( defined $entry ) {
    my ( $is_parsed, $err_msg ) = $_parse_entry->( $self, $entry, $prefs );
    if ( !$is_parsed ) {
      croak($err_msg);
    }
  }

  bless $self, $class;
  return $self;
}

######################################################################
#
# Instance methods

# Utility method for folks who want to do a ->new and then at some later
# point throw an entry onto the object.
sub parse {
  my $self  = shift;
  my $entry = shift;
  my $prefs = shift || {};

  if ( exists $self->{_key} ) {
    croak('object has already parsed an entry');
  }

  my ( $is_parsed, $err_msg ) = $_parse_entry->( $self, $entry, $prefs );
  if ( !$is_parsed ) {
    croak($err_msg);
  }

  return $self;
}

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

sub options {
  my $self    = shift;
  my $options = shift;
  my $set_options;

  if ( exists $self->{_parsed_options} ) {
    die('TODO implement get/set of options after options parsed');

  } elsif ( defined $options ) {
    $self->{_options} = $options;
    $set_options = $options;
  }

  return $set_options;
}

sub get_option {
  my $self = shift;
  my $value;

  if ( exists $self->{_options} and length $self->{_options} > 0 ) {
    if ( !exists $self->{_parsed_options} ) {
      my ( $is_parsed, $err_msg ) =
        $_split_options->( $self, $self->{_options} );
      if ( !$is_parsed ) {
        croak($err_msg);
      }
    }
    # TODO - now have parsed options, need to lookup the option from the
    # whatever, return value, if any..
  }

  return $value;
}

# TODO how distinguish between boolean and value options? Or don't,
# and leave it up to the caller to pass no data in for a boolean
# option? Hrm.
sub set_option {
  my $self         = shift;
  my $option_name  = shift;
  my $option_value = shift;

  # parse option string, if any, to internal format. update value or
  # create new option, depending.
}

sub as_string {
  my $self   = shift;
  my $string = q{};

  if ( exists $self->{_parsed_options} ) {
    # TODO should this be a as_string on a ::Options object?
    $string .= 'TODO' . q{ };
  } elsif ( exists $self->{_options} and length $self->{_options} > 0 ) {
    $string .= $self->{_options} . q{ };
  }
  $string .= $self->{_key};
  if ( exists $self->{_comment} and length $self->{_comment} > 0 ) {
    $string .= q{ } . $self->{_comment};
  }

  return $string;
}

1;

__END__

=head1 NAME

Config::OpenSSH::Authkey::Entry - authorized_keys entry handler

=head1 SYNOPSIS

  TODO

=head1 DESCRIPTION

This module parses input OpenSSH authorized_keys lines. TODO

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

Copyright 2009-2010 by Jeremy Mates.

This program is free software; you can redistribute it and/or modify it
under the Artistic license.

=cut
