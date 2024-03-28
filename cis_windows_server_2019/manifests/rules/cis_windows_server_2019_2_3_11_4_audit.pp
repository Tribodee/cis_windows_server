class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_11_4_audit {
  exec {'cis_windows_server_2019_2_3_11_4_audit_ensure_network_security_configure_encryption_types_allowed_for_kerberos_is_set_to_rc4_hmac_md5_aes128_hmac_sha1_aes256_hmac_sha1_future_encryption_types':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes','2147483644'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes'),
  }
}
