class cis_windows_server_2019::rules::cis_windows_server_2019_18_3_2_audit {
  exec {'cis_windows_server_2019_18_3_2_audit_ensure_configure_smb_v1_client_driver_is_set_to_enabled_disable_driver':
    unless => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\MrxSmb10\Start','1'),
    command => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\MrxSmb10\Start')
  }
}
