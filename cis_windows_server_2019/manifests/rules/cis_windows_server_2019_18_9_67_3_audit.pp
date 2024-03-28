class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_67_3_audit {
  exec {'cis_windows_server_2019_18_9_67_3_audit_ensure_allow_indexing_of_encrypted_files_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems')
  }
}
