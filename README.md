# Static Application Security Testing - SAST -  Resources

**Note**: This resource will be constantly updated - **Last Updated: 28/02/2023**

This resource is intended to learn from the tools that certain modules already have loaded that help detect vulnerabilities in SAST, **it is not intended to replace our tasks as analysts**.
Most of the tools that are used to detect vulnerabilities either in SAST or DAST will show **false positives**, so your duty as a cybersecurity researcher is to investigate and decide if it is a vulnerability or not.



## Static Application Security Testing - SAST - Summary

- [Static Application Security Testing - SAST](#Static-Application-Security-Testing---SAST)
- [SAST - Source Code](#SAST---Source-Code)
	- [SAST - Source Code - Angular](#SAST---Source-Code---Angular)
	- [SAST - Source Code - .NET C#](#SAST---Source-Code---NET)
	- [SAST - Source Code - Python](#SAST---Source-Code---Python)
	- [SAST - Source Code - Java](#SAST---Source-Code---Java)
	- [SAST - Source Code - Golang](#SAST---Source-Code---Golang)
	- [SAST - Source Code - PHP](#SAST---Source-Code---PHP)
	- [SAST - Source Code - PowerShell](#SAST---Source-Code---PowerShell)
	- [SAST - Source Code - Docker](#SAST---Source-Code---Docker)
	- [SAST - Source Code - Cloud](#SAST---Source-Code---Cloud)
- [SAST - OneLiners](#SAST---OneLiners)
	- [SAST - OneLiners - Source code Strings](#SAST---OneLiners---Source-code-Strings)
	- [SAST - OneLiners - Git Secrets](#SAST---OneLiners---Git-Secrets)
	- [SAST - OneLiners - Secret Keywords](#SAST---OneLiners---Secret-Keywords)
- [SAST Resources](#SAST-Resources)
	- [SAST Resources - Secrets](#SAST-Resources---Secrets)
	- [SAST Resources - Regex](#SAST-Resources---Regex)
- [SAST Tools](#SAST-Tools)
	- [SAST Tools - Search Secrets](#SAST-Tools---Search-Secrets)
	- [SAST Tools - Regex](#SAST-Tools---Regex)
- [SAST Labs](#SAST-Labs)


## Static Application Security Testing - SAST

Static application security testing (SAST), or static analysis, is a testing methodology that analyzes source code to find security vulnerabilities that make your organization’s applications susceptible to attack. SAST scans an application before the code is compiled. It’s also known as white box testing.



## SAST - Source Code

### SAST - Source Code - Angular

- [stackhawk.com/blog/angular-excessive-data-exposure-examples-and-prevention](https://www.stackhawk.com/blog/angular-excessive-data-exposure-examples-and-prevention/) - Angular Excessive Data Exposure


### SAST - Source Code - NET

- [https://docs.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/security-warnings](https://docs.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/security-warnings) - Security rules support safer libraries and applications. These rules help prevent security flaws in your program.
- [troyhunt.com/owasp-top-10-for-net-developers-part-1](https://www.troyhunt.com/owasp-top-10-for-net-developers-part-1/) - OWASP Top 10 for .NET.
- [syhunt.com/docwiki/index.php?n=Vulnerable.ASP](https://www.syhunt.com/docwiki/index.php?n=Vulnerable.ASP) - examples of vulnerable classic ASP & ASP.NET.
- [exploit-db.com/docs/47458](https://www.exploit-db.com/docs/47458) - Web API .NET Vulnerabilities.
- [codeproject.com/Articles/1116318/10-Points-to-Secure-Your-ASP-NET-MVC-Applications](https://www.codeproject.com/Articles/1116318/10-Points-to-Secure-Your-ASP-NET-MVC-Applications) - 10 Points to Secure Your ASP.NET MVC Applications
- [security-code-scan.github.io](https://security-code-scan.github.io/#Rules) - rules by security code for NET with examples.
- [github.com/guardrailsio/awesome-dotnet-security](https://github.com/guardrailsio/awesome-dotnet-security) - Awesome .NET Security Resources


### SAST - Source Code - Python

- [hackernoon.com/10-common-security-gotchas-in-python-and-how-to-avoid-them](https://hackernoon.com/10-common-security-gotchas-in-python-and-how-to-avoid-them-e19fbe265e03) - 10 common security gotchas vulnerabilties in Python.
- [kevinlondon.com/2015/07/26/dangerous-python-functions](https://www.kevinlondon.com/2015/07/26/dangerous-python-functions) - Dangerous Python Functions


### SAST - Source Code - Java

- [developer.okta.com/blog/2018/07/30/10-ways-to-secure-spring-boot](https://developer.okta.com/blog/2018/07/30/10-ways-to-secure-spring-boot) - 10 Ways to Secure Spring Boot and vulnerabilities - MAVEN.
- [gist.github.com/Mogztter/maven](https://gist.github.com/Mogztter/2560b623a99fad936b328b1dad3c9120) - Cheat Sheet: 10 Maven Security Best Practices - MAVEN
- https://deepsource.io/directory/analyzers/java/issues/JAVA-S1002 - security trustmanager java


### SAST - Source Code - Golang


### SAST - Source Code - PHP

- [github.com/dustyfresh/PHP-vulnerability-audit-cheatsheet](https://github.com/dustyfresh/PHP-vulnerability-audit-cheatsheet) - PHP Oneliners for php audit


### SAST - Source Code - PowerShell

- [github.com/PowerShell/PSScriptAnalyzer#introduction](https://github.com/PowerShell/PSScriptAnalyzer) - static code checker for PowerShell modules and scripts.


### SAST - Source Code - Docker

- [snyk.io/blog/10-docker-image-security-best-practices](https://snyk.io/blog/10-docker-image-security-best-practices/) - 10 Docker Security Best Practices
- [snyk.io/blog/10-kubernetes-security-context-settings-you-should-understand](https://snyk.io/blog/10-kubernetes-security-context-settings-you-should-understand/) - 10 Kubernetes Security Context settings you should understand.


### SAST - Source Code - Cloud

- [docs.fugue.co/FG_R00069.html](https://docs.fugue.co/FG_R00069.html) - Rules- DynamoDB tables should be encrypted with AWS.
- [docs.fugue.co/FG_R00100.html ](https://docs.fugue.co/FG_R00100.html) - Rules - S3 bucket policies should only allow requests that use HTTPS

## SAST - OneLiners

### SAST - OneLiners - Source code Strings

```bash
# try to run this command in the root directory of your source code
# change example with the keywords of vulns that you know
# can be keywords like: password, eval, secret, auth....
# *.map example to exclude some files
# exclude-dir example to exclude some dirs

egrep --color -nri "example|example2|example3|password|eval" --exclude "*.map" --exclude-dir=test
```

### SAST - OneLiners - Git Secrets

- Run commands on the root of your repository

```bash
# search for specific string on commits
git grep "keyword or expression" $(git rev-list --all)
```

```shell
# search for specific string on commits
git rev-list --all | xargs git grep "keyword or expression"
```

```shell
# search for specific file
git log -p /file/example.js
```

### SAST - OneLiners - Secret Keywords

```shell
# put this string into the burpsuite search section 
# https://github.com/h33tlit/secret-regex-list
(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]
```


## SAST Resources

- [synopsys.com/blogs/software-security/sast-vs-dast-difference](https://www.synopsys.com/blogs/software-security/sast-vs-dast-difference/) - SAST vs DAST Difference.
- [https://github.com/analysis-tools-dev/static-analysis](https://github.com/analysis-tools-dev/static-analysis) – A curated list of static analysis (SAST)
- https://github.com/cyberkartik/gpt3-vuln-scan - AI GPT-3 found hundreds of security vulnerabilities in this repo.
- [github.com/cldrn/InsecureProgrammingDB](https://github.com/cldrn/InsecureProgrammingDB) - Paulino calderon Insecure programming functions database strings
- [evdaez.com/source-code-review-simple-doctors-appointment](https://evdaez.com/index.php/2022/06/09/source-code-review-simple-doctors-appointment/) - Source code review – Simple doctor’s appointment
- [github.com/harsh-bothra/SecurityExplained](https://github.com/harsh-bothra/SecurityExplained) - Explain source code vulnerabilities and some methodologies for pentesting, vulnerable code snippets.
- [owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf](https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf) - Guide for code vulnerabilities review
- [dwheeler.com/essays/static-analysis-tools](https://dwheeler.com/essays/static-analysis-tools.html) - Static analysis tools for security
- [hdivsecurity.com/docs/sql-injection](https://hdivsecurity.com/docs/sql-injection/) - SAST & DAST
- [github.com/analysis-tools-dev/static-analysis](https://github.com/analysis-tools-dev/static-analysis) - tools for all programming languages, config files, build tools, and more.
- [hacktricks.boitatech.com.br/pentesting/pentesting-web/code-review-tools](https://hacktricks.boitatech.com.br/pentesting/pentesting-web/code-review-tools) -  Code Review Tools - Hacktrix
- [allabouttesting.org/50-point-checklist-for-secure-code-review](https://allabouttesting.org/50-point-checklist-for-secure-code-review/) - Checklist Secure Code Review identifies possible security vulnerabilities.
- [github.com/snoopysecurity/Vulnerable-Code-Snippets](https://github.com/snoopysecurity/Vulnerable-Code-Snippets) - A small collection of vulnerable code snippets.
- [hacksplaining.com/lessons](https://www.hacksplaining.com/lessons) - Learn SAST and DAST.
- [secnhack-in.cdn.ampproject.org/c/s/secnhack.in/source-code-audit-with-grep-command](https://secnhack-in.cdn.ampproject.org/c/s/secnhack.in/source-code-audit-with-grep-command/amp/) - Source Code Audit with GREP Command.
- https://infosecwriteups.com/how-i-found-aws-api-keys-using-trufflehog-and-validated-them-using-enumerate-iam-tool-cd6ba7c86d09 -  How I Found AWS API Keys using “Trufflehog” and Validated them using enumerate-iam tool

### SAST Resources - Secrets

- https://medium.com/@levshmelevv/10-000-bounty-for-exposed-git-to-rce-304c7e1f54 - $10.000 bounty for exposed .git to RCE
- [medium.com/@Dhamuharker/critical-git-repository-leaked-internal-data](https://medium.com/@Dhamuharker/critical-git-repository-leaked-internal-data-9508e0476a0e) - Critical Git Repository Leaked Internal Data
- [github.com/h33tlit/secret-regex-list](https://github.com/h33tlit/secret-regex-list) - List of regex for scraping secret API keys and juicy information.
- [github.com/zricethezav/gitleaks](https://github.com/zricethezav/gitleaks) - Protect and discover secrets using Gitleaks
- [https://github.com/Eilonh/s3crets_scanner](https://github.com/Eilonh/s3crets_scanner) - S3cret Scanner: Hunting For Secrets Uploaded To Public S3 Buckets (check the python script)
- https://www.autoregex.xyz/ -  Effortless conversions from.

### SAST Resources - Regex

- [s0md3v.medium.com/how-i-found-5-redos-vulnerabilities-in-mod-security-crs](https://s0md3v.medium.com/how-i-found-5-redos-vulnerabilities-in-mod-security-crs-ce8474877e6e) - How I found 5 ReDOS Vulnerabilities in Mod Security CRS
- [https://levelup.gitconnected.com/the-regular-expression-denial-of-service-redos-cheat-sheet-a78d0ed7d865](https://levelup.gitconnected.com/the-regular-expression-denial-of-service-redos-cheat-sheet-a78d0ed7d865) - The Regular Expression Denial of Service (ReDoS) cheat-sheet
- [https://blog.doyensec.com/2021/03/11/regexploit.html](https://blog.doyensec.com/2021/03/11/regexploit.html) - Regexploit: DoS-able Regular Expressions
- [https://medium.com/node-security/minimatch-redos-vulnerability-590da24e6d3c](https://medium.com/node-security/minimatch-redos-vulnerability-590da24e6d3c) - Minimatch ReDoS Vulnerability

## SAST Tools

- [github.com/ZupIT/horusec](https://github.com/ZupIT/horusec) - Horusec is an open source tool that improves identification of vulnerabilities in your project with just one command.
- [https://marketplace.visualstudio.com/items?itemName=HCLTechnologies.hclappscancodesweep](https://marketplace.visualstudio.com/items?itemName=HCLTechnologies.hclappscancodesweep) - HCL AppScan CodeSweep is a Code Editor extension that detects security vulnerabilities while you code.
- [https://github.com/equick/jkscerts](https://github.com/equick/jkscerts) - Check certificates in a java keystore without having to know the keystore password.
- [github.com/joernio/joern](https://github.com/joernio/joern/) - Open-source code analysis platform for C/C++/Java/Binary/Javascript/Python/Kotlin based on code property graphs.
- [github.com/Tencent/CodeAnalysis](https://github.com/Tencent/CodeAnalysis) - comprehensive platform for code analysis and issue tracking.
- [github.com/insidersec/insider](https://github.com/insidersec/insider) - Static Application Security Testing (SAST) engine focused on covering the OWASP Top 10, to make source code analysis to find vulnerabilities right in the source code.
- [github.com/Skyscanner/cfripper](https://github.com/Skyscanner/cfripper) - CFRipper is a Library and CLI security analyzer for AWS CloudFormation templates.
- [github.com/AppThreat/dep-scan](https://github.com/AppThreat/dep-scan) - Fully open-source security audit for project dependencies based on known vulnerabilities and advisories.
- [github.com/salesforce/cloudsplaining](https://github.com/salesforce/cloudsplaining) - Cloudsplaining is an AWS IAM Security Assessment tool that identifies violations of least privilege and generates a risk-prioritized report.
- [https://github.com/securego/gosec](https://github.com/securego/gosec) - Golang security checker
- https://github.com/find-sec-bugs/find-sec-bugs - The SpotBugs plugin for security audits of Java web applications and Android applications. (Also work with Kotlin, Groovy and Scala projects)
- https://github.com/denandz/sourcemapper - Extract JavaScript source trees from Sourcemap files
- https://github.com/ShiftLeftSecurity/sast-scan - Scan is a free & Open Source DevSecOps tool for performing static analysis based security testing of your applications and its dependencies. CI and Git friendly.

### SAST Tools - Search Secrets

- https://github.com/ihebski/DefaultCreds-cheat-sheet - One place for all the default credentials to assist the Blue/Red teamers activities on finding devices with default password
- https://github.com/trufflesecurity/trufflehog - Trufflehog Find credentials all over the place.
- [GitGraber - github.com/hisxo/gitGraber](https://github.com/hisxo/gitGraber) - Find sensitive data in real time for different online services github online, not local.
- [github.com/securing/DumpsterDiver](https://github.com/securing/DumpsterDiver) - Tool to search secrets in various filetypes.
- [github.com/Puliczek/awesome-list-of-secrets-in-environment-variables](https://github.com/Puliczek/awesome-list-of-secrets-in-environment-variables) - Awesome list of secrets in environment variables.
- [github.com/deepfence/SecretScanner](https://github.com/deepfence/SecretScanner) - Find secrets and passwords in container images and file systems.
- [sniferl4bs.com/2022/01/busca-credenciales-por-defecto-de-productos-en-la-terminal-con-pass-station](https://sniferl4bs.com/2022/01/busca-credenciales-por-defecto-de-productos-en-la-terminal-con-pass-station/) - Search default credentials of some producs. 
- [github.com/ztgrace/changeme](https://github.com/ztgrace/changeme) - A default credential scanner.
- [github.com/MarkoH17/Spray365](https://github.com/MarkoH17/Spray365)- identifie valid credentials for office 365.
- [github.com/defensahacker/secrets-finder](https://github.com/defensahacker/secrets-finder) - Simple script to find secrets inside source code folders BASH.
- [github.com/s0md3v/hardcodes](https://github.com/s0md3v/hardcodes) - find hardcoded strings from source code
- [github.com/arijitdirghanji/Find-Hardcoded](https://github.com/arijitdirghanji/Find-Hardcoded) - Find hardcode Android string into files.
- [github.com/zricethezav/gitleaks](https://github.com/zricethezav/gitleaks) - Protect and discover secrets using Gitleaks.

### SAST Tools - Regex

- [redos-checker.surge.sh](https://redos-checker.surge.sh/) -  Check your regex safety.
- [devina.io/redos-checker](https://devina.io/redos-checker) -  Check your regex safety.
- [redosdetector.com](https://redosdetector.com/) - detect regex with posible redos.
- [regexr.com](https://regexr.com/) -RegExr is an online tool to **learn**, **build**, & **test** Regular Expressions.
- [regextester.com](https://www.regextester.com/96605) - regex testing.
- [github.com/2bdenny/ReScue](https://github.com/2bdenny/ReScue) - An automated tool for the detection of regexes' slow-matching vulnerabilities.
- [gist.github.com/s0md3v/redox.py](https://gist.github.com/s0md3v/52a44ba8918c25d89c82579232a27ff3) - Scan a directory for exploitable regular expressions.
- [github.com/doyensec/regexploit](https://github.com/doyensec/regexploit) - Find regular expressions which are vulnerable to ReDoS
- [https://jex.im/regulex/](https://jex.im/regulex/) - JavaScript Regular Expression Visualizer.
- [https://regexper.com/](https://regexper.com/) - Explain regex
- https://www.debuggex.com/  - regex

**Tip**

```sh
#check for regex
time node -e '/<VULNERABLE REGEX>/.test("<exploitstring>")'
# example normal
time node -e '/[^/]+\\.[^/]+$/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
# results: time node  0.18, if the time is > 1.00 it is vulnerable
```


## SAST Labs

- [github.com/mgreiler/code-reviews](https://github.com/mgreiler/code-reviews) - The redeem application, is a small JavaScript and Express application that has quite a few of issues.
- [github.com/OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) - The OWASP NodeGoat project provides an environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.
- [github.com/chuckfw/owaspbwa](https://github.com/chuckfw/owaspbwa) - OWASP Broken Web Applications Project, a collection of vulnerable web applications.
- [github.com/ShiftLeftSecurity/tarpit-java](https://github.com/ShiftLeftSecurity/tarpit-java) - Tarpit - A Web application seeded with vulnerabilities, rootkits, backdoors & data leaks
- [application.security/kontra](https://application.security/) - Application Security Training
- [github.com/owasp/SecureCodingDojo](https://github.com/owasp/SecureCodingDojo) - The Secure Coding Dojo is a platform for delivering secure coding knowledge.
- [owasp.org/SecureCodingDojo/codereview101/#!#codereview101_inputValidation](https://owasp.org/SecureCodingDojo/codereview101/#!#codereview101_inputValidation) - Want to test your ability to identify security issues during code review.
- https://github.com/Yavuzlar/VulnLab - for SAST and DAST, A web vulnerability lab project developed by Yavuzlar.
