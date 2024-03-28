class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_4_2_audit {
  exec {'cis_windows_server_2019_18_8_4_2_audit_ensure_remote_host_allows_delegation_of_non_exportable_credentials_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds')
  }
}
