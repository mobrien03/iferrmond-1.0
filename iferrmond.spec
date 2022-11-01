#
# spec file for package iferrmond-1.0
#
# Copyright (c) 2021 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           iferrmond
Version:        1.0
Release:        1.2
Summary:        Interface monitoring daemon
License:        GPL
Group:          Applications/Utilities
Vendor:         mobrien03@gmail.com
Packager:       mobrien03@gmail.com
Source:         /home/michael/src/iferrmond-1.0-1.2.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Prefix:         /usr

%description
iferrmond is a daemon intended to run under control of systemd, designed to 
monitor configured network interfaces for kernel statistics errors, and write
events/alerts to syslog.

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
%make_install

%post 
if [ "$1" = 1 ]; then
#   If previous .conf has been saved, put that in-place, and inform installer
    [ -f /tmp/iferrmond_rpmsave.conf ] && cp -p /tmp/iferrmond_rpmsave.conf %{prefix}/local/etc/iferrmond.conf 
    [ -f /tmp/iferrmond_rpmsave.conf ] && echo "Note: /tmp/iferrmond_rpmsave.conf moved to %{prefix}/local/etc/iferrmond.conf"
    [ -f /tmp/iferrmond_rpmsave.conf ] && echo "Note: Original template exists as: %{prefix}/local/share/iferrmond/iferrmond_default.conf"
    [ -f /tmp/iferrmond_rpmsave.conf ] && rm -f /tmp/iferrmond_rpmsave.conf 
    
#   Create dedicated User and Group for iferrmond
    /usr/sbin/groupadd --gid 9479 iferrmond
    /usr/sbin/useradd  --uid 9152 --gid 9479 --comment "interface monitoring daemon" -e "" --no-create-home --shell /sbin/nologin iferrmond
    
#   Enable iferrmond service to systemd, and reload systemd's configuration
    systemctl enable %{name}.service
    systemctl daemon-reload

#   Inform installer to validate the .conf file before starting iferrmond
    echo ""
    echo "====> NOTE <===="
    echo "Please validate the configuration directives in %{prefix}/local/etc/iferrmond.conf"
    echo "before starting iferrmond with 'systemctl start iferrmond'"
    echo ""
fi

%preun
systemctl stop %{name}.service
systemctl disable %{name}.service
[ -f %{prefix}/local/etc/iferrmond.conf ] && cp -p %{prefix}/local/etc/iferrmond.conf /tmp/iferrmond_rpmsave.conf
[ -f /tmp/iferrmond_rpmsave.conf ] && echo "Note: A copy of %{prefix}/local/etc/iferrmond.conf has been saved as /tmp/iferrmond_rpmsave.conf"

%postun
if [ "$1" = 0 ]; then
#   Remove /var/run directory for cleanup
    [ -d /var/run/iferrmond ] && echo "Note: /var/run/iferrmond will be removed."
    [ -d /var/run/iferrmond ] && rmdir /var/run/iferrmond

#   Perform daemon-reload for systemd
    systemctl daemon-reload

#   Remove the user account - on RH, default is group by same name is removed too
    /usr/sbin/userdel iferrmond

#   if not Redhat, also run groupdel
    if [ ! -f /etc/redhat-release ]; then
        groupdel iferrmond
    fi
fi

%files
%{prefix}/local/bin/iferrmond
%{prefix}/local/etc/iferrmond.conf
%{prefix}/local/share/iferrmond/iferrmond_default.conf
%{prefix}/lib/systemd/system/iferrmond.service

%if 0%{?rhel}
  %{prefix}/local/share/man/man1/iferrmond.1
%else
  %{prefix}/local/man/man1/iferrmond.1
%endif


%changelog

