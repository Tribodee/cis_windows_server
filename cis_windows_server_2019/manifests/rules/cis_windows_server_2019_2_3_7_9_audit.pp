class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_7_9_audit {
  exec {'cis_windows_server_2019_2_3_7_9_audit_ensure_interactive_logon_smart_card_removal_behavior_is_set_to_lock_workstation_or_higher':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption'),
  }
}
