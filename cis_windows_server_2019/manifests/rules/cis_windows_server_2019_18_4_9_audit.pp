class cis_windows_server_2019::rules::cis_windows_server_2019_18_4_9_audit {
  exec {'cis_windows_server_2019_18_4_9_audit_ensure_mss_screensavergraceperiod_the_time_in_seconds_before_the_screen_saver_grace_period_expires_0_recommended_is_set_to_enabled_5_or_fewer_seconds':
    unless => cis_windows_server_2019::check_gpresult_folder_id_value_less ('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod', '5, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod')
  }
}
