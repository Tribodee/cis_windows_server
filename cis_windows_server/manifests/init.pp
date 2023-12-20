class cis_windows_server {
  exec {'1.1.1_ensure_enforce_password_history_is_set_to_24_or_more_password':
    unless  => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "PasswordHistorySize" | findstr "24"',
    # command => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"',
    command => 'C:\Windows\System32\cmd.exe /c echo "1.1.1 its not ready"',
    logoutput => true,
  }
  exec {'1.1.2_ensure_maximum_password_age_is_set_to_90_or_fewer_days_but_not_0':
    unless  => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "MaxPwdAge" | findstr "7776000000000 "',
    # command => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"',
    command => 'C:\Windows\System32\cmd.exe /c echo "1.1.2 its not ready"',
    logoutput => true,
  }
  exec{'1.1.3_ensure_minimum_password_age_is_set_to_1_or_more_day':
    unless  => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "MinimumPasswordAge" | findstr "864000000000 "',
    # command => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"',
    command => 'C:\Windows\System32\cmd.exe /c echo "1.1.3 its not ready"',
    logoutput => true,   
  }
  exec {'1.1.4_ensure_minimum_password_length_is_set_to_8_or_more_character':
    unless  => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "MinimumPasswordLength" | findstr "8 "',
    # command => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"',
    command => 'C:\Windows\System32\cmd.exe /c echo "1.1.4 its not ready"',
    logoutput => true,   
  }
  exec {'1.1.5_ensure_password_must_meet_complexity_requirements_is_set_to_enabled':
    unless  => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PasswordComplexity" | findstr "1 "',
    # command => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"',
    command => 'C:\Windows\System32\cmd.exe /c echo "1.1.5 its not ready"',
    logoutput => true, 
  }
  exec {'1.1.6_ensure_store_passwords_using_reversible_encryption_is_set_to_disabled':
    unless  => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "StorePasswordsUsingReversibleEncryption" | findstr "0"',
    # command => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"',
    command => 'C:\Windows\System32\cmd.exe /c echo "1.1.6 its not ready"',
    logoutput => true, 
  }
  exec {'1.2.1_ensure_account_lockout_duration_is_set_to_15_or_more_minute':
    unless  => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LockoutDuration" | findstr "900 "',
    # command => 'C:\Windows\System32\cmd.exe /c REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"',
    command => 'C:\Windows\System32\cmd.exe /c echo "1.2.1 its not ready"',
    logoutput => true, 
  }
}
