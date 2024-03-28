class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_4_1_audit {
  exec {'cis_windows_server_2019_2_3_4_1_audit_ensure_devices_allowed_to_format_and_eject_removable_media_is_set_to_administrators':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD','0'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD'),
  }
}
