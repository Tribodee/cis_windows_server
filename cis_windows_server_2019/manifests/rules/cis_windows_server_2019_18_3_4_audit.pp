class cis_windows_server_2019::rules::cis_windows_server_2019_18_3_4_audit {
  exec {'cis_windows_server_2019_18_3_4_audit_ensure_enabled_structured_exception_handling_overwrite_protection_sehop_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\DisableExceptionChainValidation','1'),
    command => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\DisableExceptionChainValidation')
  }
}
