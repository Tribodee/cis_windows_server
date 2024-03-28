class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_11_10_audit {
  exec {'cis_windows_server_2019_2_3_11_10_audit_ensure_network_security_minimum_session_security_for_ntlm_ssp_based_including_secure_rpc_servers_is_set_to_require_ntlmv2_session_security_require_128_bit_encryption':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec','537395200'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec'),
  }
}
