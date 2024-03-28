class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_17_4_audit {
  exec {'cis_windows_server_2019_2_3_17_4_audit_ensure_user_account_control_behavior_of_the_elevation_prompt_for_standard_users_is_set_to_automatically_deny_elevation_requests':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser','0'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser'),
  }
}
