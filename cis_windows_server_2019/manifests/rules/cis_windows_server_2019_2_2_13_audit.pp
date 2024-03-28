class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_13_audit {
  exec {'cis_windows_server_2019_2_2_13_audit_ensure_create_a_pagefile_is_set_to_administrators':
    unless  => cis_windows_server_2019::check_gpresult_users('CreatePagefilePrivilege','Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('CreatePagefilePrivilege'),
  }
}
