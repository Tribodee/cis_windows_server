class cis_windows_server_2019::rules::cis_windows_server_2019_18_3_6_audit {
  exec {'cis_windows_server_2019_18_3_6_audit_ensure_netbt_node_type_configuration_is_set_to_enabled_p_node':
    unless => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\NetBT\Parameters\NodeType','1'),
    command => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\NetBT\Parameters\NodeType')
 }
}
