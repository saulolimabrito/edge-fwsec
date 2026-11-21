# Edge FWSec RPM. The Go binaries are built reproducibly by `make linux`
# (hashes in SHA256SUMS) and packaged here unchanged; the SELinux module is
# compiled during the RPM build.
%global efw_version %{?efw_version}%{!?efw_version:0.0.0}
%global efw_release %{?efw_release}%{!?efw_release:0.dev}
%global efw_commit %{?efw_commit}%{!?efw_commit:unknown}
%global selinuxtype targeted
%global debug_package %{nil}
# Binaries are prebuilt, stripped and reproducible; do not post-process them
# (also lets the x86_64 package be assembled on an aarch64 builder).
%global __os_install_post %{nil}

Name:           edge-fwsec
Version:        %{efw_version}
Release:        %{efw_release}%{?dist}
Summary:        Edge firewall appliance: nftables, NetworkManager and web console
License:        LicenseRef-Not-Yet-Licensed
URL:            https://github.com/saulolimabrito/edge-fwsec
Source0:        edge-fwsec-%{version}-%{_arch}.tar.gz
ExclusiveArch:  x86_64 aarch64

BuildRequires:  selinux-policy-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  bzip2
Requires:       nftables
Requires:       NetworkManager
Requires:       systemd
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
Requires(post): policycoreutils
%{?systemd_requires}
%{?selinux_requires}

%description
Single-node edge firewall appliance for Rocky Linux 10: stateful firewall
with nftables, interfaces, VLANs and routes through NetworkManager, changes
applied with a confirmation deadline and automatic rollback, and an HTTPS
web console. Built from commit %{efw_commit}.

%prep
%setup -q -n edge-fwsec-%{version}

%build
make -f %{_datadir}/selinux/devel/Makefile -C packaging/selinux efw.pp
bzip2 -9 packaging/selinux/efw.pp

%install
install -Dm0755 bin/efw-agent %{buildroot}%{_bindir}/efw-agent
install -Dm0755 bin/efw-web   %{buildroot}%{_bindir}/efw-web
install -Dm0755 bin/efwctl    %{buildroot}%{_bindir}/efwctl
install -Dm0644 packaging/systemd/efw-agent.service %{buildroot}%{_unitdir}/efw-agent.service
install -Dm0644 packaging/systemd/efw-web.service   %{buildroot}%{_unitdir}/efw-web.service
install -Dm0644 packaging/systemd/efw-firstboot.service %{buildroot}%{_unitdir}/efw-firstboot.service
install -Dm0644 packaging/sysusers.d/edge-fwsec.conf %{buildroot}%{_sysusersdir}/edge-fwsec.conf
install -Dm0644 packaging/tmpfiles.d/edge-fwsec.conf %{buildroot}%{_tmpfilesdir}/edge-fwsec.conf
install -Dm0644 packaging/sysctl.d/90-edge-fwsec.conf %{buildroot}%{_sysctldir}/90-edge-fwsec.conf
install -Dm0644 packaging/selinux/efw.pp.bz2 %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/efw.pp.bz2
install -d -m0755 %{buildroot}%{_sysconfdir}/edge-fwsec
install -d -m0700 %{buildroot}%{_sharedstatedir}/efw
install -d -m0700 %{buildroot}%{_sharedstatedir}/efw-web
install -Dm0644 SHA256SUMS %{buildroot}%{_docdir}/%{name}/SHA256SUMS

%pre
%sysusers_create_compat packaging/sysusers.d/edge-fwsec.conf
%selinux_relabel_pre -s %{selinuxtype}

%post
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/efw.pp.bz2
%tmpfiles_create edge-fwsec.conf
%sysctl_apply 90-edge-fwsec.conf
%systemd_post efw-agent.service efw-web.service efw-firstboot.service

%preun
%systemd_preun efw-web.service efw-agent.service efw-firstboot.service

%postun
%systemd_postun_with_restart efw-agent.service efw-web.service
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} efw
fi

%posttrans
%selinux_relabel_post -s %{selinuxtype}
restorecon -R %{_bindir}/efw-agent %{_bindir}/efw-web %{_sharedstatedir}/efw %{_sharedstatedir}/efw-web %{_sysconfdir}/edge-fwsec /run/efw >/dev/null 2>&1 || :

%files
%doc README.md docs/architecture.md docs/threat-model.md docs/support-matrix.md
%{_docdir}/%{name}/SHA256SUMS
%{_bindir}/efw-agent
%{_bindir}/efw-web
%{_bindir}/efwctl
%{_unitdir}/efw-agent.service
%{_unitdir}/efw-web.service
%{_unitdir}/efw-firstboot.service
%{_sysusersdir}/edge-fwsec.conf
%{_tmpfilesdir}/edge-fwsec.conf
%{_sysctldir}/90-edge-fwsec.conf
%{_datadir}/selinux/packages/%{selinuxtype}/efw.pp.bz2
%dir %{_sysconfdir}/edge-fwsec
%attr(0700,root,root) %dir %{_sharedstatedir}/efw
%attr(0700,efw-web,efw-web) %dir %{_sharedstatedir}/efw-web

%changelog
* Sat Nov 21 2026 Saulo Brito <100214355+saulolimabrito@users.noreply.github.com> - 0.4.0-0.1
- Pre-release packaging: agent, console, systemd units, SELinux module.
