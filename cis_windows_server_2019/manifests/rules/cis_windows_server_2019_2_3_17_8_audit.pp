class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_17_8_audit {
  exec {'cis_windows_server_2019_2_3_17_8_audit_ensure_user_account_control_switch_to_the_secure_desktop_when_prompting_for_elevation_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop'),
  }
}
