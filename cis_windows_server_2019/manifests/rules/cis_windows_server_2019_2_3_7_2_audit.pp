class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_7_2_audit {
  exec {'cis_windows_server_2019_2_3_7_2_audit_ensure_interactive_logon_do_not_display_last_user_name_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName'),
  }
}
