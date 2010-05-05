use inc::Module::Install;

# Define metadata
name 'Config-OpenSSH-Authkey';
all_from 'lib/Config/OpenSSH/Authkey.pm';

# Specific dependencies
test_requires 'Test::More' => '0.72';

WriteAll;
