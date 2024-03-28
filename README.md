# This project is going to audit all of "windows server NOT DC! " from CIS Base line Windows Server 2019 V1.30 is correclty setting or not?  
So if you want to audit the policy what should you do next? Basicly many ppl will check by registry key cause it's will show the every policy setting but to be honest It's that actual policy?  
Don't forget one thing! every windows server it's connect to Domain Controller. So the policy setting should follow by DC right?  
So now why we not get actual setting from command build-in powershell?  
First if we want to check the policy setting in windows firewall. Now you go with  
```
Get-NetFireWallprofile -PolicyStore ActiveStore | Select-Object * -ExcludeProperty PS*, Cim*,Caption*,ElementName*,InstanceID*,Description*,DisabledInterfaceAliases*, __* 
```
It's going to get from ActiveStore and the question is what is -PolicyStore ActiveStore?  
From microsoft article **-PolicyStore**   
_Policy store is a container for firewall and IPsec policy_  
And then **ActiveStore**?  
_This store contains the currently active policy, which is the sum of all policy stores that apply to the computer.  
This is the resultant set of policy (RSOP) for the local computer (the sum of all GPOs that apply to the computer),   
and the local stores (the PersistentStore,the static Windows service hardening (WSH), and the configurable WSH)_  

Every command audit we use the string check, So that's means if this command apply all of modules it's not good enough with performance  
But thank god puppet have custom facts, So what custom facts gonna do  
Custom facts is going to run script from ruby and then get the value from script sound good right?  
So what facts you want to get?  
That's correct Get-NetFireWallProfile ~~  
What's next? We already have firewall What we going to do next _from CIS Base Line_ some task is going to check "Auditpolicy"?  
And yes powershell can handle this task  
```
auditpol /get /category:* /r
```
So it simple this command just show Auditpolicy that's all.  
And the last thing is the main course 80% of this CIS base line use this command  
```
gpresult /r /scope:computer /v
```
This command going to show all of policy setting maybe get from firewall from registry from anything else that's why we use this command  
And custom them to facts.  

    
I'm glad you here that's means you strongest cause you can read my english skill to the end sorry about that  


ref
https://learn.microsoft.com/en-us/powershell/module/netsecurity/show-netfirewallrule?view=windowsserver2022-ps
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get
