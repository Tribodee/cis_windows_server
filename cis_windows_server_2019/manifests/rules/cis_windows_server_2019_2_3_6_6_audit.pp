class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_6_6_audit {
  exec {'cis_windows_server_2019_2_3_6_6_audit_ensure_domain_member_require_strong_windows_2000_or_later_session_key_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey'),
  }
}
