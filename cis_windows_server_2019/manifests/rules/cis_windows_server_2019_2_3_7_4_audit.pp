class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_7_4_audit {
  $gpresult_raw = $facts['gpresult_facts']
  $data = $gpresult_raw['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText']['Computer Setting']
  exec {'cis_windows_server_2019_2_3_7_4_audit_configure_interactive_logon_message_text_for_users_attempting_to_log_on':
    unless   => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c ((('${data}') -match ('NOTICE (TH)')) -match (('${data}') -match ('NOTICE (EN)')))",
    command  => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText')",
  }
}
