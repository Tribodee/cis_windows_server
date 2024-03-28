class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_11_5_audit {
  exec {'cis_windows_server_2019_2_3_11_5_audit_ensure_network_security_do_not_store_lan_manager_hash_value_on_next_password_change_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'),
  }
}
