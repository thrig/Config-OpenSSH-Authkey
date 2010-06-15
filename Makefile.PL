use inc::Module::Install;
name 'Config-OpenSSH-Authkey';
all_from 'lib/Config/OpenSSH/Authkey.pm';
license 'artistic';

perl_version '5.006';
requires 'Carp'            => 0;
requires 'IO::Handle'      => 0;
test_requires 'Test::More' => 0;

resources
  license    => 'http://dev.perl.org/licenses/artistic.html',
  repository => 'http://github.com/thrig/Config-OpenSSH-Authkey',
  bugtracker =>
  'https://rt.cpan.org/Public/Dist/Display.html?Name=Config-OpenSSH-Authkey';

WriteAll;

