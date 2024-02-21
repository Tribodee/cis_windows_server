#Solution 2
# Facter.add(:gpresult_facts) do
#     setcode do
#         gpresult_output = Facter::Core::Execution.execute('gpresult /r /scope:computer /v')
#         resultant_set = ""
#         parsing_resultant_set = false
#         gpresult_output.each_line do |line|
#             line_strip = line.strip
#             parsing_resultant_set = true if line_strip =~ /^Resultant Set Of Policies for Computer/
#             resultant_set << "#{line_strip}\n" if parsing_resultant_set
#         end
#     resultant_set.strip
#     end
# end

# Solution 7##BEST
# require 'json'

# Facter.add(:gpresult_facts) do
#     setcode do

#     gpresult_output = Facter::Core::Execution.execute('gpresult /r /scope:computer /v')
#     resultant_set = []
#     current_result = {}

#     gpresult_output.each_line do |line|
#         line_strip = line.strip
#         if line_strip =~ /^Resultant Set Of Policies for Computer/
#             current_result = {}
#         elsif line_strip =~ /^(Policy|ValueName):\s+(.+)$/
#             key = $1
#             value = $2.strip
#             current_result[key] = [value]
#         elsif line_strip.empty? && !current_result.empty?
#             resultant_set << current_result
#             current_result = {}
#         elsif line_strip.empty? && current_result.empty?
#         elsif current_result.key?('Policy')
#             current_result['Policy'] << line_strip.strip
#         end
#     end
    
#     resultant_set << current_result unless current_result.empty?
#     JSON.pretty_generate(resultant_set)
#     end
# end

#Solution 8 ##Almost complete
# require 'json'

# Facter.add(:gpresult_facts) do
#     setcode do
#     gpresult_output = Facter::Core::Execution.execute('gpresult /r /scope:computer /v')
#     resultant_set = []
#     current_result = {}
#     gpresult_output.each_line do |line|
#         line_strip = line.strip
#         if line_strip =~ /^Resultant Set Of Policies for Computer/
#             current_result = {}
#         elsif line_strip =~ /^(Policy|ValueName):\s+(.+)$/
#             key = $1
#             value = $2.strip
#             current_result[key] = value
#         elsif line_strip.empty? && !current_result.empty?
#             resultant_set << current_result
#             current_result = {}
#         elsif line_strip.empty? && current_result.empty?
#             # Skip empty lines without any data
#         elsif current_result.key?('Policy')
#             # If 'Policy' key already exists, append the value to the existing array
#             current_result['Policy'] << line_strip.strip
#         end
#     end
#     # Include the last result if there's any
#     resultant_set << current_result unless current_result.empty?
#     # resultant_set.to_json
#     JSON.pretty_generate(resultant_set)
#     end
# end

#can make =>
# require 'json'

# Facter.add(:gpresult_facts) do
#   setcode do
#     gpresult_output = Facter::Core::Execution.execute('gpresult /r /scope:computer /v')
#     resultant_set = []
#     current_result = {}

#     gpresult_output.each_line do |line|
#       line_strip = line.strip

#       if line_strip =~ /^Resultant Set Of Policies for Computer/
#         current_result = {}
#       elsif line_strip =~ /^(Policy|ValueName):\s+(.+)$/
#         key = $1
#         value = $2.strip
#         current_result[key] = value
#       elsif line_strip.empty? && !current_result.empty?
#         resultant_set << current_result
#         current_result = {}
#       elsif line_strip.empty? && current_result.empty?
#         # Skip empty lines without any data
#       elsif current_result.key?('Policy')
#         # If 'Policy' key already exists, append the value to the existing array
#         current_result['Policy'] << line_strip.strip
#       end
#     end

#     # Include the last result if there's any
#     resultant_set << current_result unless current_result.empty?

#     # Replace colons with rockets in the resulting JSON
#     json_result = JSON.pretty_generate(resultant_set).gsub(/":/, '" =>')

#     json_result
#   end
# end


# #almost
# require 'json'

# Facter.add(:gpresult_facts) do
#   setcode do
#     gpresult_output = Facter::Core::Execution.execute('gpresult /r /scope:computer /v')
#     resultant_set = []
#     current_result = {}

#     gpresult_output.each_line do |line|
#       line_strip = line.strip

#       if line_strip =~ /^Resultant Set Of Policies for Computer/
#         current_result = {}
#       elsif line_strip =~ /^(Policy|ValueName):\s+(.+)$/
#         key = $1
#         value = $2.strip
#         if key == 'Policy'
#           current_result[value] = {}
#         elsif key == 'ValueName'
#           current_result[current_result.keys.last]['ValueName'] = value
#         end
#       elsif line_strip.empty? && !current_result.empty?
#         resultant_set << current_result
#         current_result = {}
#       elsif line_strip.empty? && current_result.empty?
#         # Skip empty lines without any data
#       elsif !current_result.empty? && current_result.key?('Policy')
#         # If 'Policy' key already exists, append the value to the existing array
#         current_result[current_result.keys.last]['ComputerSetting'] = line_strip.strip
#       end
#     end

#     # Include the last result if there's any
#     resultant_set << current_result unless current_result.empty?

#     # Replace colons with rockets in the resulting JSON
#     json_result = JSON.pretty_generate(resultant_set).gsub(/":/, '" =>')

#     json_result
#   end
# end