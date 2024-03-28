class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_28_3_audit {
  exec {'cis_windows_server_2019_18_8_28_3_audit__ensure_do_not_enumerate_connected_users_on_domain_joined_computers_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers')
  }
}
