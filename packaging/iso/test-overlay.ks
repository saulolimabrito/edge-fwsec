# TEST-ONLY additions appended to edge-fwsec.ks for unattended VM tests.
# Never shipped: they erase the first disk and add an SSH key.
zerombr
clearpart --all --initlabel
autopart --type=lvm --nohome
rootpw --lock
sshkey --username=root "@SSH_PUBKEY@"
reboot
