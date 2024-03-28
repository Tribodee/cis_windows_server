class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_28_4_audit {
  exec {'cis_windows_server_2019_18_8_28_4_audit_ensure_enumerate_local_users_on_domain_joined_computers_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers')
  }
}
