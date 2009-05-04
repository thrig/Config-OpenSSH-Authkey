use warnings;
use strict;

use Test::More tests => 4;
BEGIN { use_ok('Config::OpenSSH::Authkey') }
ok( defined $Config::OpenSSH::Authkey::VERSION, '$VERSION defined' );

BEGIN { use_ok('Config::OpenSSH::Authkey::Entry') }
ok( defined $Config::OpenSSH::Authkey::Entry::VERSION, '$VERSION defined' );

exit 0;
