class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_6_4_audit {
  exec {'cis_windows_server_2019_2_3_6_4_audit_ensure_domain_member_disable_machine_account_password_changes_is_set_to_disabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange','0'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange'),
  }
}
