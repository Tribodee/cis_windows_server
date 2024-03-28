class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_10_8_audit {
  exec {'cis_windows_server_2019_2_3_10_8_audit_configure_network_access_remotely_accessible_registry_paths':
    unless   => cis_windows_server_2019::check_gpresult_users('MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine','System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine'),
  }
}
