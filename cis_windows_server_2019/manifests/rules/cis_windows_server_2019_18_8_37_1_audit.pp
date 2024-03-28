class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_37_1_audit {
  exec {'cis_windows_server_2019_18_8_37_1_audit_ensure_enable_rpc_endpoint_mapper_client_authentication_is_set_to_enabled_ms_only':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('')
  }
}
