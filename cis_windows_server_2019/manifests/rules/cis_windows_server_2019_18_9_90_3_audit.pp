class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_90_3_audit {
  exec {'cis_windows_server_2019_18_9_90_3_audit_ensure_prevent_internet_explorer_security_prompt_for_windows_installer_scripts_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\Installer\SafeForScripting', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\Installer\SafeForScripting')
  }
}
