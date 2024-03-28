class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_10_9_audit {
  exec {'cis_windows_server_2019_2_3_10_9_audit_configure_network_access_remotely_accessible_registry_paths_and_sub_paths':
    unless   => cis_windows_server_2019::check_gpresult_users('MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine','System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine'),
  }
}
