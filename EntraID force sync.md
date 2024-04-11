- force AAD Dir sync update Delta only
``` 
Invoke-Command -ComputerName <servername> -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
```

- force AAD Dir sync update Full
```
Invoke-Command -ComputerName <servername> -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Initial}
```
