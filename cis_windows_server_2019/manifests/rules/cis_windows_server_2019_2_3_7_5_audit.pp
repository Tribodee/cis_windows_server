class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_7_5_audit {
  exec {'cis_windows_server_2019_2_3_7_5_audit_configure_interactive_logon_message_title_for_users_attempting_to_log_on':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption','TISCO Warning Statement'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption'),
  }
}
