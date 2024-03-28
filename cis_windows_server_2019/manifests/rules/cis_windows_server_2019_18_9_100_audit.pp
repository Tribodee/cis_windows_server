class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_100_audit {
  exec {'cis_windows_server_2019_18_9_100_audit_ensure_turn_on_powershell_script_block_logging_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging')
  }
}
