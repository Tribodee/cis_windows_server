require 'facter'
require 'json'
Facter.add(:auditpolicy) do
    confine :kernel => 'windows'
    setcode do
    auditpolicy_raw = Facter::Core::Execution.execute('auditpol /get /category:* /r')
    policy_settings = {}
    auditpolicy_raw.each_line do |line|
        parts = line.strip.split(',')
        policy_audit = parts[2]
        value = parts[4]
        next if policy_audit.nil? && value.nil?
        policy_settings[policy_audit.to_sym] = value
    end
    policy_settings
    end
end
