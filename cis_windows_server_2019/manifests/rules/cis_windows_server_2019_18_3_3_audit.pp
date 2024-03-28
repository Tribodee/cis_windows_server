class cis_windows_server_2019::rules::cis_windows_server_2019_18_3_3_audit {
  exec {'cis_windows_server_2019_18_3_3_audit_ensure_configure_smb_v1_server_driver_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1','0'),
    command => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1')
  }
}
