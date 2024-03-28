class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_6_5_audit {
  exec {'cis_windows_server_2019_2_3_6_5_audit_ensure_domain_member_maximum_machine_account_password_age_is_set_to_30_or_fewer_days_but_not_0':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge','30'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge'),
  }
}
