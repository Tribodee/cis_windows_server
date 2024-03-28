class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_7_1_audit {
  exec {'cis_windows_server_2019_2_3_7_1_audit_ensure_interactive_logon_do_not_require_ctrl_alt_del_is_set_to_disabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD','0'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD'),
  }
}
