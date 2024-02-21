#Testing Modules auditpolicy
class cis_windows_server_2019::rules::test2 {
  exec {'test007':
    unless => cis_windows_server_2019::check_auditpol('User Account Management','Success'),
    command => cis_windows_server_2019::check_auditpol_value('User Account Management'),
  }
}
