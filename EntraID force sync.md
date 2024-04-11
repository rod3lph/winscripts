- force AAD Dir sync update Delta only
``` 
Invoke-Command -ComputerName cdlfdc01 -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
```

- force AAD Dir sync update Full
```
Invoke-Command -ComputerName cdlfdc01 -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Initial}
```
