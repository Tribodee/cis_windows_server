class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_17_5_audit {
  exec {'cis_windows_server_2019_2_3_17_5_audit_ensure_user_account_control_detect_application_installations_and_prompt_for_elevation_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection'),
  }
}
