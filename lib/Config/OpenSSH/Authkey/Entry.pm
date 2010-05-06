# -*- Perl -*-
#
# Representation of individual OpenSSH authorized_keys entries, based on
# a study of the sshd(8) manual, along with the OpenSSH 5.2 sources.
# This module only weakly validates the data; in particular, no effort
# is made to confirm whether the key options are actual valid options
# for the version of OpenSSH in question.

package Config::OpenSSH::Authkey::Entry;

use strict;
use warnings;

use Carp qw(croak);

our $VERSION = '0.03';

# This limit is set for various things under OpenSSH code. Used here to
# limit length of authorized_keys lines.
my $MAX_PUBKEY_BYTES = 8192;

# Delved from sshd(8), auth-options.c of OpenSSH 5.2. Insensitive match
# required, as OpenSSH uses strncasecmp(3).
my $AUTHKEY_OPTION_NAME_RE = qr/(?i)[a-z0-9_-]+/;

######################################################################
#
# Data Parsing & Utility Methods - Internal

my $_split_options = sub {
  my $self    = shift;
  my $options = shift;

  my $parsed_option_count = 0;

  # Inspected OpenSSH auth-options.c,v 1.44 to derive this lexer:
  #
  # In OpenSSH, unparsable options result in a call to bad_options and
  # the entry being rejected. This module is more permissive, in that
  # any option name is allowed, regardless of whether OpenSSH supports
  # such an option or whether the option is the correct type (boolean
  # vs. string value). This makes the module more future proof, at the
  # cost of allowing garbage through.
  #
  # Options are stored using a list of hashrefs, which allows for
  # duplicate options, and preserves the order of options. Also, an
  # index is maintained to speed lookups of the data, and to note if
  # duplicate options exist. This is due to inconsistent handling by
  # OpenSSH_5.1p1 of command="" vs. from="" vs. environment="" options
  # when multiple entries are present. Methods are offered to detect and
  # cleanup such (hopefully rare) duplicate options.

OPTION_LEXER: {
    # String Argument Options - value is a perhaps empty string enclosed
    # in double quotes. Internal double quotes are allowed, but only if
    # these are preceded by a backslash.
    if (
      $options =~ m/ \G ($AUTHKEY_OPTION_NAME_RE)="( (?: \\"|[^"] )*? )"
        (?:,|[ \t]+)? /cgx
      ) {
      my $option_name = $1;
      my $option_value = $2 || q{};

      push @{ $self->{_parsed_options} },
        { name => $option_name, value => $option_value };
      push @{ $self->{_parsed_options_index}->{$option_name} },
        $#{ $self->{_parsed_options} };
      $parsed_option_count++;

      redo OPTION_LEXER;
    }

    # Boolean options - mere presence enables them in OpenSSH
    if ( $options =~ m/ \G ($AUTHKEY_OPTION_NAME_RE) (?:,|[ \t]+)? /cgx ) {
      my $option_name = $1;

      push @{ $self->{_parsed_options} }, { name => $option_name };
      push @{ $self->{_parsed_options_index}->{$option_name} },
        $#{ $self->{_parsed_options} };

      $parsed_option_count++;
      redo OPTION_LEXER;
    }
  }

  $self->{_parsed_options_count} = $parsed_option_count;
  return $parsed_option_count;
};

# Utility routine in event user passes in a complete new options string
# via the options method.
my $_clear_parsed_options = sub {
  my $self = shift;
  delete $self->{$_}
    for qw(_parsed_options _parsed_options_index _parsed_options_count);
  return 1;
};

my $_parsed_options_as_string = sub {
  my $self = shift;
  return join(
    q{,},
    map {
      $_->{name}
        . ( exists $_->{value} ? '="' . $_->{value} . '"' : q{} )
      } @{ $self->{_parsed_options} }
  );
};

my $_parse_entry = sub {
  my $self = shift;
  my $entry = shift || q{};

  my ( $options, $key, $comment, $protocol, $keytype );

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
    # Optional trailing comment (user@host, usually)
    if ( defined $key and $entry =~ m/ \G (.+) /cgx ) {
      $comment = $1;

      last ENTRY_LEXER;
    }

    # SSH2 RSA or DSA public key
    if ( !defined $key
      and $entry =~
      m/ \G ( ssh-(rsa|dss) [ \t]+? [A-Za-z0-9+\/]+ =* ) [ \t]* /cgx ) {

      $key = $1;
      # follow the -t argument option to ssh-keygen(1)
      $keytype = $2 eq 'rsa' ? 'rsa' : 'dsa';
      $protocol = 2;

      redo ENTRY_LEXER;
    }

    # SSH1 RSA public key
    if ( !defined $key
      and $entry =~ m/ \G ( \d{3,5} [ \t]+? \d+ [ \t]+? \d+ ) [ \t]* /cgx ) {

      $key      = $1;
      $keytype  = 'rsa1';
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
    $self->{_keytype}  = $keytype;

    if ( defined $options ) {
      $options =~ s/\s*$//;
      $self->{_options} = $options;
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

  my $self = {};

  if ( defined $entry ) {
    my ( $is_parsed, $err_msg ) = $_parse_entry->( $self, $entry );
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

sub key {
  my $self = shift;
  my $key  = shift;
  if ( defined $key ) {
    my ( $is_parsed, $err_msg ) = $_parse_entry->( $self, $key );
    if ( !$is_parsed ) {
      croak($err_msg);
    }
  }
  return $self->{_key};
}

sub protocol {
  shift->{_protocol};
}

sub keytype {
  shift->{_keytype};
}

sub comment {
  my $self    = shift;
  my $comment = shift;
  if ( defined $comment ) {
    $self->{_comment} = $comment;
  }
  return $self->{_comment};
}

sub unset_comment {
  my $self = shift;
  delete $self->{_comment};
  return 1;
}

# The leading (optional!) options can be dealt with as a string
# (options, unset_options), or if parsed, as individual options
# (get_option, set_option, unset_option).

sub options {
  my $self    = shift;
  my $options = shift;

  if ( defined $options ) {
    $self->{_options} = $options;
    $_clear_parsed_options->($self) if exists $self->{_parsed_options};
  }

  return exists $self->{_parsed_options}
    ? $_parsed_options_as_string->($self)
    : $self->{_options};
}

sub unset_options {
  my $self = shift;
  $_clear_parsed_options->($self) if exists $self->{_parsed_options};
  delete $self->{_options};
  return 1;
}

# NOTE - boolean return the name of the option, while string value
# options the string. This may change, depending on how I like how this
# is handled...
sub get_option {
  my $self        = shift;
  my $option_name = shift;
  my @values;

  if ( exists $self->{_options} and length $self->{_options} > 0 ) {
    if ( !exists $self->{_parsed_options} ) {
      $_split_options->( $self, $self->{_options} );
    }
  }

  if ( exists $self->{_parsed_options_index}->{$option_name} ) {
    @values =
      map { $self->{_parsed_options}->[$_]->{value} || $option_name }
      @{ $self->{_parsed_options_index}->{$option_name} };
  }

  return wantarray ? @values : $values[0];
}

# Sets an option. To enable a boolean option, only supply the option
# name, and pass no value data.
sub set_option {
  my $self         = shift;
  my $option_name  = shift || croak('set_option requires an option name');
  my $option_value = shift;

  if ( exists $self->{_options} and length $self->{_options} > 0 ) {
    if ( !exists $self->{_parsed_options} ) {
      $_split_options->( $self, $self->{_options} );
    }
  }

  if ( exists $self->{_parsed_options_index}->{$option_name} ) {
    if ( defined $option_value ) {
      $self->{_parsed_options}
        ->[ $self->{_parsed_options_index}->{$option_name}->[0] ]->{value} =
        $option_value;
    }

    # And wipe any duplicate entries for this option (should be rare)
    if ( @{ $self->{_parsed_options_index}->{$option_name} } > 1 ) {
      for my $index ( @{ $self->{_parsed_options_index}->{$option_name} }
        [ 1 .. $#{ $self->{_parsed_options_index}->{$option_name} } ] ) {
        splice @{ $self->{_parsed_options} }, $index, 1;
      }
      splice @{ $self->{_parsed_options_index}->{$option_name} }, 1;
    }
  } else {
    push @{ $self->{_parsed_options} },
      {
      name => $option_name,
      ( defined $option_value ? ( value => $option_value ) : () )
      };
    push @{ $self->{_parsed_options_index}->{$option_name} },
      $#{ $self->{_parsed_options} };
  }

  return 1;
}

sub unset_option {
  my $self        = shift;
  my $option_name = shift;
  my $count       = 0;

  if ( exists $self->{_options} and length $self->{_options} > 0 ) {
    if ( !exists $self->{_parsed_options} ) {
      $_split_options->( $self, $self->{_options} );
    }
  }

  if ( exists $self->{_parsed_options_index}->{$option_name} ) {
    for my $index ( @{ $self->{_parsed_options_index}->{$option_name} } ) {
      splice @{ $self->{_parsed_options} }, $index, 1;
      ++$count;
    }
    delete $self->{_parsed_options_index}->{$option_name};
  }

  return $count;
}

sub as_string {
  my $self   = shift;
  my $string = q{};

  if ( exists $self->{_parsed_options} ) {
    $string .= $_parsed_options_as_string->($self) . q{ };

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

Config::OpenSSH::Authkey::Entry - authorized_keys file entry handler

=head1 SYNOPSIS

This module is used by L<Config::OpenSSH::Authkey>, though can be used
standalone:
  
  my $entry = Config::OpenSSH::Authkey::Entry->new();
  
  # assuming $fh is opened to an authorized_keys file...
  eval {
    $entry->key($fh->getline);
    if ($entry->protocol == 1) {
      warn "warning: deprecated SSHv1 key detected ...\n";
    }
  };
  ...

=head1 DESCRIPTION

This module parses lines from OpenSSH C<authorized_keys> files, and
offers various methods to interact with the data. The B<AUTHORIZED_KEYS
FILE FORMAT> section of sshd(8) details the format of these lines. I use
the term entry to mean a line from an C<authorized_keys> file.

Errors are thrown via C<die> or C<croak>, notably when parsing an entry
via the B<new> or B<key> methods.

=head1 METHODS

=over 4

=item B<new> I<optional entry to parse>

Constructor. Optionally accepts an C<authorized_keys> file entry to
parse.

=item B<key> I<optional key to parse>

Returns the public key material. If passed a string, will attempt to
parse that string as a new key (and options, and comment, if those
are present).

=item B<keytype>

Returns the type of the key, either C<rsa1> for a SSHv1 key, or C<rsa>
or C<dsa> for the two different SSHv2 key types. This is the same format
as the ssh-keygen(1) C<-t> option accepts.

=item B<protocol>

Returns the major SSH protocol version of the key, 1 or 2.

Note that SSHv1 has been replaced by SSHv2 for over a decade as of 2010.
I strongly recommend that SSHv1 be disabled.

=item B<comment> I<optional new comment>

Returns the comment, if any, of the parsed entry. ssh-keygen(1) defaults
to C<user@host> for this field. If a string is passed, updates the
comment to that string.

=item B<unset_comment>

Deletes the comment.

=item B<options> I<optional new option string>

Returns any options set in the entry as a comma separated value string,
or, if passed a string, sets that string as the new option set.

  # get
  my $option_str = $entry->options();
  
  # set
  $entry->options('from="127.0.0.1",no-agent-forwarding');

=item B<unset_options>

Deletes all the options.

=item B<get_option> I<option name>

Returns the value (or values) for a named option. OpenSSH does allow
duplicate entries for options, though in most cases this method will
only return a single value. Options are boolean or string value; boolean
options return the name of the method, while string options return the
string value:

  # returns 'no-agent-forwarding'
  $entry->get_option('no-agent-forwarding');
  
  # returns '127.0.0.1'
  $entry->get_option('from');

In scalar context, only the first option is returned. In list context, a
list of one (or rarely more) values will be returned.

=item B<set_option> I<option name>, I<optional value>

Enables an option, or with an additional argument, sets the string value
for that option.

  # boolean
  $entry->set_option('no-agent-forwarding');
  
  # string value
  $entry->set_option(from => '127.0.0.1');

=item B<unset_option> I<option name>

Deletes the named option.

=item B<as_string>

Returns the entry formatted as an OpenSSH authorized_keys line.

=back

=head1 BUGS

No known bugs. Newer versions of this module may be available from CPAN.
  
If the bug is in the latest version, send a report to the author.
Patches that fix problems or add new features are welcome.

=head1 SEE ALSO

sshd(8), ssh-keygen(1), L<Config::OpenSSH::Authkey|Config::OpenSSH::Authkey>

=head1 AUTHOR

Jeremy Mates, E<lt>jmates@sial.orgE<gt>

=head1 COPYRIGHT

Copyright 2009-2010 by Jeremy Mates.

This program is free software; you can redistribute it and/or modify it
under the Artistic license.

=cut
