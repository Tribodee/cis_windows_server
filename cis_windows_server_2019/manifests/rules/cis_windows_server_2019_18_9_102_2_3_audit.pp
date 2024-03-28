class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_102_2_3_audit {
  exec {'cis_windows_server_2019_18_9_102_2_3_audit_ensure_allow_unencrypted_traffic_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic')
  }
}
