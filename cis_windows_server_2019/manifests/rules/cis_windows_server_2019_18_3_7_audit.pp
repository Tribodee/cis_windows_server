class cis_windows_server_2019::rules::cis_windows_server_2019_18_3_7_audit {
  exec {'cis_windows_server_2019_18_3_7_audit_ensure_wdigest_authentication_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential', '', 'disabled'),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential')
  }
}
