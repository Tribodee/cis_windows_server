class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_31_4_audit {
  exec {'cis_windows_server_2019_18_9_31_4_audit_ensure_turn_off_shell_protocol_protected_mode_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior')
  }
}
