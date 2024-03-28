class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_37_2_audit {
  exec {'cis_windows_server_2019_18_8_37_2_audit_ensure_restrict_unauthenticated_rpc_clients_is_set_to_enabled_authenticated_ms_only':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients')
  }
}
