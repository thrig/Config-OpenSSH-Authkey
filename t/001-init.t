use warnings;
use strict;

use Test::More tests => 2;
BEGIN { use_ok('Config::OpenSSH::Authkey') }
ok( defined $Config::OpenSSH::Authkey::VERSION, '$VERSION defined' );
