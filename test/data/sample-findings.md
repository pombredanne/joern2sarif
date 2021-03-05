------------------------------------
Title: Sensitive Data Leak: Security-sensitive data is leaked via `req` to log in `anonymous`
Score: 2.5
Categories: [a3-sensitive-data-exposure]
Flow ids: [4355481239626404686]
Description: HTTP data is written to a log file in this flow. This data may be visible to a third party that has access to the logs, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.


## Countermeasures

This vulnerability can be prevented by not writing HTTP data directly to the log or by encrypting it in advance.

## Additional information

**[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**

**[CWE-117](https://cwe.mitre.org/data/definitions/117.html)**

**[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**
-------------------------------------
 _______________________________________________________________________________________
 | tracked            | lineNumber| method                | file                        |
 |======================================================================================|
 | req                | 6         | anonymous             | vulnerabilities/sensitive.js|
 | req.query          | 7         | anonymous             | vulnerabilities/sensitive.js|
 | p2                 | N/A       | <operator>.assignment |                             |
 | p1                 | N/A       | <operator>.assignment |                             |
 | _req$query         | 7         | anonymous             | vulnerabilities/sensitive.js|
 | _req$query.password| 9         | anonymous             | vulnerabilities/sensitive.js|
 | p2                 | N/A       | <operator>.assignment |                             |
 | p1                 | N/A       | <operator>.assignment |                             |
 | password           | 9         | anonymous             | vulnerabilities/sensitive.js|
 | password           | 10        | anonymous             | vulnerabilities/sensitive.js|
 | p1                 | N/A       | ^__whatwg.console^.log|                             |


------------------------------------
Title: Sensitive Data Leak: Security-sensitive data is leaked via `req` to log in `anonymous1`
Score: 2.5
Categories: [a3-sensitive-data-exposure]
Flow ids: [4355481239626404674]
Description: HTTP data is written to a log file in this flow. This data may be visible to a third party that has access to the logs, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.


## Countermeasures

This vulnerability can be prevented by not writing HTTP data directly to the log or by encrypting it in advance.

## Additional information

**[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**

**[CWE-117](https://cwe.mitre.org/data/definitions/117.html)**

**[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**
-------------------------------------
 ______________________________________________________________________________________
 | tracked           | lineNumber| method                | file                        |
 |=====================================================================================|
 | req               | 13        | anonymous1            | vulnerabilities/sensitive.js|
 | req.query.password| 15        | anonymous1            | vulnerabilities/sensitive.js|
 | p1                | N/A       | ^__whatwg.console^.log|                             |


------------------------------------
Title: Sensitive Data Leak: Security-sensitive data is leaked via `req` to log in `anonymous2`
Score: 2.5
Categories: [a3-sensitive-data-exposure]
Flow ids: [4355481239626404730]
Description: HTTP data is written to a log file in this flow. This data may be visible to a third party that has access to the logs, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.


## Countermeasures

This vulnerability can be prevented by not writing HTTP data directly to the log or by encrypting it in advance.

## Additional information

**[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**

**[CWE-117](https://cwe.mitre.org/data/definitions/117.html)**

**[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**
-------------------------------------
 ________________________________________________________________________________________
 | tracked             | lineNumber| method                | file                        |
 |=======================================================================================|
 | req                 | 20        | anonymous2            | vulnerabilities/sensitive.js|
 | req.query           | 21        | anonymous2            | vulnerabilities/sensitive.js|
 | p2                  | N/A       | <operator>.assignment |                             |
 | p1                  | N/A       | <operator>.assignment |                             |
 | _req$query2         | 21        | anonymous2            | vulnerabilities/sensitive.js|
 | _req$query2.username| 22        | anonymous2            | vulnerabilities/sensitive.js|
 | p2                  | N/A       | <operator>.assignment |                             |
 | p1                  | N/A       | <operator>.assignment |                             |
 | username            | 22        | anonymous2            | vulnerabilities/sensitive.js|
 | username            | 27        | anonymous2            | vulnerabilities/sensitive.js|
 | p2                  | N/A       | <operator>.assignment |                             |
 | p1                  | N/A       | <operator>.assignment |                             |
 | data.username       | 27        | anonymous2            | vulnerabilities/sensitive.js|
 | data                | 31        | anonymous2            | vulnerabilities/sensitive.js|
 | p1                  | N/A       | ^__whatwg.console^.log|                             |


------------------------------------
Title: Sensitive Data Leak: Security-sensitive data is leaked via `req` to log in `anonymous2`
Score: 2.5
Categories: [a3-sensitive-data-exposure]
Flow ids: [4355481239626404754]
Description: HTTP data is written to a log file in this flow. This data may be visible to a third party that has access to the logs, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.


## Countermeasures

This vulnerability can be prevented by not writing HTTP data directly to the log or by encrypting it in advance.

## Additional information

**[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**

**[CWE-117](https://cwe.mitre.org/data/definitions/117.html)**

**[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**
-------------------------------------
 ________________________________________________________________________________________
 | tracked             | lineNumber| method                | file                        |
 |=======================================================================================|
 | req                 | 20        | anonymous2            | vulnerabilities/sensitive.js|
 | req.query           | 21        | anonymous2            | vulnerabilities/sensitive.js|
 | p2                  | N/A       | <operator>.assignment |                             |
 | p1                  | N/A       | <operator>.assignment |                             |
 | _req$query2         | 21        | anonymous2            | vulnerabilities/sensitive.js|
 | _req$query2.password| 23        | anonymous2            | vulnerabilities/sensitive.js|
 | p2                  | N/A       | <operator>.assignment |                             |
 | p1                  | N/A       | <operator>.assignment |                             |
 | password            | 23        | anonymous2            | vulnerabilities/sensitive.js|
 | password            | 28        | anonymous2            | vulnerabilities/sensitive.js|
 | p2                  | N/A       | <operator>.assignment |                             |
 | p1                  | N/A       | <operator>.assignment |                             |
 | data.password       | 28        | anonymous2            | vulnerabilities/sensitive.js|
 | data                | 31        | anonymous2            | vulnerabilities/sensitive.js|
 | p1                  | N/A       | ^__whatwg.console^.log|                             |


------------------------------------
Title: Open Redirect: HTTP Request parameters are used in HTTP redirects via `req` in `anonymous`
Score: 3.0
Categories: [a1-injection]
Flow ids: [4355481239626404860]
Description: HTTP Request parameters are not escaped and used in a HTTP redirect. This indicates an open redirect which can be exploited by an attacker to launch phishing attacks and/or steal sensitive data.

## Countermeasures

 This vulnerability can be prevented by ensuring that users cannot arbitrarily control where your page redirects them to.

## Additional information

**[CWE-601](https://cwe.mitre.org/data/definitions/601.html)**

**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 __________________________________________________________________________________________________________
 | tracked                           | lineNumber| method                     | file                       |
 |=========================================================================================================|
 | req                               | 8         | anonymous                  | vulnerabilities/redirect.js|
 | req.query.path                    | 9         | anonymous                  | vulnerabilities/redirect.js|
 | p2                                | N/A       | <operator>.assignment      |                            |
 | p1                                | N/A       | <operator>.assignment      |                            |
 | followPath                        | 9         | anonymous                  | vulnerabilities/redirect.js|
 | followPath                        | 12        | anonymous                  | vulnerabilities/redirect.js|
 | p2                                | N/A       | <operator>.addition        |                            |
 | ret                               | N/A       | <operator>.addition        |                            |
 | "http://example.com/" + followPath| 12        | anonymous                  | vulnerabilities/redirect.js|
 | p1                                | N/A       | ^express.Response^.redirect|                            |


------------------------------------
Title: Open Redirect: HTTP Request parameters are used in HTTP redirects via `req` in `anonymous1`
Score: 3.0
Categories: [a1-injection]
Flow ids: [4355481239626404840]
Description: HTTP Request parameters are not escaped and used in a HTTP redirect. This indicates an open redirect which can be exploited by an attacker to launch phishing attacks and/or steal sensitive data.

## Countermeasures

 This vulnerability can be prevented by ensuring that users cannot arbitrarily control where your page redirects them to.

## Additional information

**[CWE-601](https://cwe.mitre.org/data/definitions/601.html)**

**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 ________________________________________________________________________________________________
 | tracked                 | lineNumber| method                     | file                       |
 |===============================================================================================|
 | req                     | 17        | anonymous1                 | vulnerabilities/redirect.js|
 | req.query.url           | 18        | anonymous1                 | vulnerabilities/redirect.js|
 | p1                      | N/A       | encodeURI                  |                            |
 | ret                     | N/A       | encodeURI                  |                            |
 | encodeURI(req.query.url)| 18        | anonymous1                 | vulnerabilities/redirect.js|
 | p2                      | N/A       | <operator>.assignment      |                            |
 | p1                      | N/A       | <operator>.assignment      |                            |
 | url                     | 18        | anonymous1                 | vulnerabilities/redirect.js|
 | url                     | 20        | anonymous1                 | vulnerabilities/redirect.js|
 | p1                      | N/A       | ^express.Response^.redirect|                            |


------------------------------------
Title: Open redirect: HTTP Request parameters are used in HTTP redirects via `res` in `anonymous1`
Score: 3.0
Categories: [A1-injection]
Flow ids: [4355481239626406017]
Description: HTTP request parameters are used in a HTTP redirect without validation.
 Using a specially crafted URL, an attacker could launch phishing attacks and steal user credentials.
 ## Countermeasures
 - Ensure data passed in HTTP requests does not control their final destination.
 ## Additional information
 **[CWE-601](https://cwe.mitre.org/data/definitions/601.html)**
 **[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 _______________________________________________________________________________
 | tracked| lineNumber| method                     | file                       |
 |==============================================================================|
 | res    | 17        | anonymous1                 | vulnerabilities/redirect.js|
 | res    | 20        | anonymous1                 | vulnerabilities/redirect.js|
 | p0     | N/A       | ^express.Response^.redirect|                            |


------------------------------------
Title: Open redirect: HTTP Request parameters are used in HTTP redirects via `res` in `anonymous`
Score: 3.0
Categories: [A1-injection]
Flow ids: [4355481239626406041]
Description: HTTP request parameters are used in a HTTP redirect without validation.
 Using a specially crafted URL, an attacker could launch phishing attacks and steal user credentials.
 ## Countermeasures
 - Ensure data passed in HTTP requests does not control their final destination.
 ## Additional information
 **[CWE-601](https://cwe.mitre.org/data/definitions/601.html)**
 **[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 _______________________________________________________________________________
 | tracked| lineNumber| method                     | file                       |
 |==============================================================================|
 | res    | 8         | anonymous                  | vulnerabilities/redirect.js|
 | res    | 12        | anonymous                  | vulnerabilities/redirect.js|
 | p0     | N/A       | ^express.Response^.redirect|                            |


------------------------------------
Title: Open redirect: HTTP Request parameters are used in HTTP redirects via `req` in `anonymous1`
Score: 3.0
Categories: [A1-injection]
Flow ids: [4355481239626406065]
Description: HTTP request parameters are used in a HTTP redirect without validation.
 Using a specially crafted URL, an attacker could launch phishing attacks and steal user credentials.
 ## Countermeasures
 - Ensure data passed in HTTP requests does not control their final destination.
 ## Additional information
 **[CWE-601](https://cwe.mitre.org/data/definitions/601.html)**
 **[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 ________________________________________________________________________________________________
 | tracked                 | lineNumber| method                     | file                       |
 |===============================================================================================|
 | req                     | 17        | anonymous1                 | vulnerabilities/redirect.js|
 | req.query.url           | 18        | anonymous1                 | vulnerabilities/redirect.js|
 | p1                      | N/A       | encodeURI                  |                            |
 | ret                     | N/A       | encodeURI                  |                            |
 | encodeURI(req.query.url)| 18        | anonymous1                 | vulnerabilities/redirect.js|
 | p2                      | N/A       | <operator>.assignment      |                            |
 | p1                      | N/A       | <operator>.assignment      |                            |
 | url                     | 18        | anonymous1                 | vulnerabilities/redirect.js|
 | url                     | 20        | anonymous1                 | vulnerabilities/redirect.js|
 | p1                      | N/A       | ^express.Response^.redirect|                            |


------------------------------------
Title: Open redirect: HTTP Request parameters are used in HTTP redirects via `req` in `anonymous`
Score: 3.0
Categories: [A1-injection]
Flow ids: [4355481239626406099]
Description: HTTP request parameters are used in a HTTP redirect without validation.
 Using a specially crafted URL, an attacker could launch phishing attacks and steal user credentials.
 ## Countermeasures
 - Ensure data passed in HTTP requests does not control their final destination.
 ## Additional information
 **[CWE-601](https://cwe.mitre.org/data/definitions/601.html)**
 **[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 __________________________________________________________________________________________________________
 | tracked                           | lineNumber| method                     | file                       |
 |=========================================================================================================|
 | req                               | 8         | anonymous                  | vulnerabilities/redirect.js|
 | req.query.path                    | 9         | anonymous                  | vulnerabilities/redirect.js|
 | p2                                | N/A       | <operator>.assignment      |                            |
 | p1                                | N/A       | <operator>.assignment      |                            |
 | followPath                        | 9         | anonymous                  | vulnerabilities/redirect.js|
 | followPath                        | 12        | anonymous                  | vulnerabilities/redirect.js|
 | p2                                | N/A       | <operator>.addition        |                            |
 | ret                               | N/A       | <operator>.addition        |                            |
 | "http://example.com/" + followPath| 12        | anonymous                  | vulnerabilities/redirect.js|
 | p1                                | N/A       | ^express.Response^.redirect|                            |


------------------------------------
Title: XSS: HTTP data to HTML via `req` in `anonymous`
Score: 5.0
Categories: [A7-XSS]
Flow ids: [4355481239626403781]
Description: HTTP request data is used in rendering HTML without validation.
 By sending a specially crafted request, an attacker could inject malicious code into the website and compromise the confidentiality and integrity of the data exchanged between the service and users.
 ## Countermeasures
 - Sanitize and validate HTTP data before passing it back to the user.
 ## Additional information
 **[CWE-79](https://cwe.mitre.org/data/definitions/79.html)**
 **[OWASP-A7](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS))**
-------------------------------------
 _________________________________________________________________________________________
 | tracked              | lineNumber| method               | file                         |
 |========================================================================================|
 | req                  | 91        | anonymous            | vulnerabilities/dep-lodash.js|
 | req.params.userConfig| 92        | anonymous            | vulnerabilities/dep-lodash.js|
 | p2                   | N/A       | <operator>.assignment|                              |
 | p1                   | N/A       | <operator>.assignment|                              |
 | userConfig           | 92        | anonymous            | vulnerabilities/dep-lodash.js|
 | userConfig           | 94        | anonymous            | vulnerabilities/dep-lodash.js|
 | source               | 33        | merge                | vulnerabilities/dep-lodash.js|
 | source[attr]         | 38        | merge                | vulnerabilities/dep-lodash.js|
 | p2                   | N/A       | <operator>.assignment|                              |
 | p1                   | N/A       | <operator>.assignment|                              |
 | target[attr]         | 38        | merge                | vulnerabilities/dep-lodash.js|
 | target               | 33        | merge                | vulnerabilities/dep-lodash.js|
 | config               | 94        | anonymous            | vulnerabilities/dep-lodash.js|
 | config               | 95        | anonymous            | vulnerabilities/dep-lodash.js|
 | p2                   | N/A       | <operator>.addition  |                              |
 | ret                  | N/A       | <operator>.addition  |                              |
 | "Config is" + config | 95        | anonymous            | vulnerabilities/dep-lodash.js|


------------------------------------
Title: XSS: HTTP data to HTML via `req` in `anonymous`
Score: 5.0
Categories: [A7-XSS]
Flow ids: [4355481239626403815]
Description: HTTP request data is used in rendering HTML without validation.
 By sending a specially crafted request, an attacker could inject malicious code into the website and compromise the confidentiality and integrity of the data exchanged between the service and users.
 ## Countermeasures
 - Sanitize and validate HTTP data before passing it back to the user.
 ## Additional information
 **[CWE-79](https://cwe.mitre.org/data/definitions/79.html)**
 **[OWASP-A7](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS))**
-------------------------------------
 ____________________________________________________________________________________________
 | tracked                        | lineNumber| method               | file                  |
 |===========================================================================================|
 | req                            | 6         | anonymous            | vulnerabilities/xss.js|
 | req.query.name                 | 7         | anonymous            | vulnerabilities/xss.js|
 | p2                             | N/A       | <operator>.assignment|                       |
 | p1                             | N/A       | <operator>.assignment|                       |
 | name                           | 7         | anonymous            | vulnerabilities/xss.js|
 | name                           | 8         | anonymous            | vulnerabilities/xss.js|
 | p2                             | N/A       | <operator>.addition  |                       |
 | ret                            | N/A       | <operator>.addition  |                       |
 | "<h1> Hello :" + name          | 8         | anonymous            | vulnerabilities/xss.js|
 | p1                             | N/A       | <operator>.addition  |                       |
 | ret                            | N/A       | <operator>.addition  |                       |
 | "<h1> Hello :" + name + "</h1>"| 8         | anonymous            | vulnerabilities/xss.js|


------------------------------------
Title: XSS: HTTP data to HTML via `req` in `anonymous1`
Score: 5.0
Categories: [A7-XSS]
Flow ids: [4355481239626403844]
Description: HTTP request data is used in rendering HTML without validation.
 By sending a specially crafted request, an attacker could inject malicious code into the website and compromise the confidentiality and integrity of the data exchanged between the service and users.
 ## Countermeasures
 - Sanitize and validate HTTP data before passing it back to the user.
 ## Additional information
 **[CWE-79](https://cwe.mitre.org/data/definitions/79.html)**
 **[OWASP-A7](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS))**
-------------------------------------
 _________________________________________________________________________________________
 | tracked              | lineNumber| method               | file                         |
 |========================================================================================|
 | req                  | 97        | anonymous1           | vulnerabilities/dep-lodash.js|
 | req.params.userConfig| 98        | anonymous1           | vulnerabilities/dep-lodash.js|
 | p2                   | N/A       | <operator>.assignment|                              |
 | p1                   | N/A       | <operator>.assignment|                              |
 | userConfig           | 98        | anonymous1           | vulnerabilities/dep-lodash.js|
 | userConfig           | 100       | anonymous1           | vulnerabilities/dep-lodash.js|
 | value                | 45        | pathAssignment       | vulnerabilities/dep-lodash.js|
 | value                | 56        | pathAssignment       | vulnerabilities/dep-lodash.js|
 | p2                   | N/A       | <operator>.assignment|                              |
 | p1                   | N/A       | <operator>.assignment|                              |
 | obj[key]             | 56        | pathAssignment       | vulnerabilities/dep-lodash.js|
 | obj                  | 45        | pathAssignment       | vulnerabilities/dep-lodash.js|
 | config               | 100       | anonymous1           | vulnerabilities/dep-lodash.js|
 | config               | 101       | anonymous1           | vulnerabilities/dep-lodash.js|
 | p2                   | N/A       | <operator>.addition  |                              |
 | ret                  | N/A       | <operator>.addition  |                              |
 | "Config is" + config | 101       | anonymous1           | vulnerabilities/dep-lodash.js|


------------------------------------
Title: XSS: HTTP data to HTML via `req` in `anonymous`
Score: 5.0
Categories: [A7-XSS]
Flow ids: [4355481239626403878]
Description: HTTP request data is used in rendering HTML without validation.
 By sending a specially crafted request, an attacker could inject malicious code into the website and compromise the confidentiality and integrity of the data exchanged between the service and users.
 ## Countermeasures
 - Sanitize and validate HTTP data before passing it back to the user.
 ## Additional information
 **[CWE-79](https://cwe.mitre.org/data/definitions/79.html)**
 **[OWASP-A7](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS))**
-------------------------------------
 _______________________________________________________________________________
 | tracked          | lineNumber| method               | file                   |
 |==============================================================================|
 | req              | 6         | anonymous            | vulnerabilities/loop.js|
 | req.body.users   | 7         | anonymous            | vulnerabilities/loop.js|
 | p2               | N/A       | <operator>.assignment|                        |
 | p1               | N/A       | <operator>.assignment|                        |
 | obj              | 7         | anonymous            | vulnerabilities/loop.js|
 | obj[i]           | 11        | anonymous            | vulnerabilities/loop.js|
 | p1               | N/A       | ^__ecma.Array^.push  |                        |
 | p0               | N/A       | ^__ecma.Array^.push  |                        |
 | someArr          | 11        | anonymous            | vulnerabilities/loop.js|
 | someArr          | 15        | anonymous            | vulnerabilities/loop.js|
 | p0               | N/A       | ^__ecma.Array^.join  |                        |
 | ret              | N/A       | ^__ecma.Array^.join  |                        |
 | someArr.join(",")| 15        | anonymous            | vulnerabilities/loop.js|


------------------------------------
Title: Sensitive Data Leak: Attacker controlled data used in redirect via `req` in `anonymous`
Score: 5.0
Categories: [a1-injection]
Flow ids: [4355481239626404860]
Description: An attacker can redirect traffic from the application. This way the attacker could perform phishing attacks and/or steal sensitive data.


## Countermeasures

This vulnerability can be prevented by validating all the data that is used to redirect users on different pages or website and by alerting the user before doing so.
-------------------------------------
 __________________________________________________________________________________________________________
 | tracked                           | lineNumber| method                     | file                       |
 |=========================================================================================================|
 | req                               | 8         | anonymous                  | vulnerabilities/redirect.js|
 | req.query.path                    | 9         | anonymous                  | vulnerabilities/redirect.js|
 | p2                                | N/A       | <operator>.assignment      |                            |
 | p1                                | N/A       | <operator>.assignment      |                            |
 | followPath                        | 9         | anonymous                  | vulnerabilities/redirect.js|
 | followPath                        | 12        | anonymous                  | vulnerabilities/redirect.js|
 | p2                                | N/A       | <operator>.addition        |                            |
 | ret                               | N/A       | <operator>.addition        |                            |
 | "http://example.com/" + followPath| 12        | anonymous                  | vulnerabilities/redirect.js|
 | p1                                | N/A       | ^express.Response^.redirect|                            |


------------------------------------
Title: Sensitive Data Leak: Attacker controlled data used in redirect via `req` in `anonymous1`
Score: 5.0
Categories: [a1-injection]
Flow ids: [4355481239626404840]
Description: An attacker can redirect traffic from the application. This way the attacker could perform phishing attacks and/or steal sensitive data.


## Countermeasures

This vulnerability can be prevented by validating all the data that is used to redirect users on different pages or website and by alerting the user before doing so.
-------------------------------------
 ________________________________________________________________________________________________
 | tracked                 | lineNumber| method                     | file                       |
 |===============================================================================================|
 | req                     | 17        | anonymous1                 | vulnerabilities/redirect.js|
 | req.query.url           | 18        | anonymous1                 | vulnerabilities/redirect.js|
 | p1                      | N/A       | encodeURI                  |                            |
 | ret                     | N/A       | encodeURI                  |                            |
 | encodeURI(req.query.url)| 18        | anonymous1                 | vulnerabilities/redirect.js|
 | p2                      | N/A       | <operator>.assignment      |                            |
 | p1                      | N/A       | <operator>.assignment      |                            |
 | url                     | 18        | anonymous1                 | vulnerabilities/redirect.js|
 | url                     | 20        | anonymous1                 | vulnerabilities/redirect.js|
 | p1                      | N/A       | ^express.Response^.redirect|                            |


------------------------------------
Title: Sensitive data from an external API response is leaked via log or persistent storage
Score: 7.0
Categories: [A3-sensitive-data-exposure]
Flow ids: [4355481239626403908]
Description: HTTP data is written to a log file or persisted in an insecure storage in this flow.
 This data may be visible to a third party that has access to the logs or the local storage, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.
 ## Countermeasures
 - This vulnerability can be prevented by not writing HTTP data directly to the log and the persistent storage or by sanitizing or obfuscating the data in advance.
 ## Additional information
 **[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**
 **[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**
 **[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**
-------------------------------------
 _______________________________________________________________________________________
 | tracked                        | lineNumber| method    | file                        |
 |======================================================================================|
 | console.log(req.query.password)| 15        | anonymous1| vulnerabilities/sensitive.js|
 | console.log(req.query.password)| 15        | anonymous1| vulnerabilities/sensitive.js|


------------------------------------
Title: Sensitive data from an external API response is leaked via log or persistent storage
Score: 7.0
Categories: [A3-sensitive-data-exposure]
Flow ids: [4355481239626403926]
Description: HTTP data is written to a log file or persisted in an insecure storage in this flow.
 This data may be visible to a third party that has access to the logs or the local storage, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.
 ## Countermeasures
 - This vulnerability can be prevented by not writing HTTP data directly to the log and the persistent storage or by sanitizing or obfuscating the data in advance.
 ## Additional information
 **[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**
 **[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**
 **[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**
-------------------------------------
 ___________________________________________________________________________________
 | tracked                       | lineNumber| method    | file                     |
 |==================================================================================|
 | console.log("user registered")| 51        | anonymous1| vulnerabilities/nosqli.js|
 | console.log("user registered")| 51        | anonymous1| vulnerabilities/nosqli.js|


------------------------------------
Title: Sensitive data from an external API response is leaked via log or persistent storage
Score: 7.0
Categories: [A3-sensitive-data-exposure]
Flow ids: [4355481239626403944]
Description: HTTP data is written to a log file or persisted in an insecure storage in this flow.
 This data may be visible to a third party that has access to the logs or the local storage, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.
 ## Countermeasures
 - This vulnerability can be prevented by not writing HTTP data directly to the log and the persistent storage or by sanitizing or obfuscating the data in advance.
 ## Additional information
 **[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**
 **[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**
 **[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**
-------------------------------------
 ____________________________________________________________________________
 | tracked              | lineNumber| method   | file                        |
 |===========================================================================|
 | console.log(password)| 10        | anonymous| vulnerabilities/sensitive.js|
 | console.log(password)| 10        | anonymous| vulnerabilities/sensitive.js|


------------------------------------
Title: Prototype Pollution: Attacker-controlled object leading to RCE or XSS via `req` in `check`
Score: 7.0
Categories: [A1-injection]
Flow ids: [4355481239626405988]
Description: An attacker-controlled object is used in a procedure that can change the `Object.prototype` property.
 This might allow an attacker to execute arbitrary code remotely, extract sensitive data from the system and compromise the integrity of the system completely.
 ## Countermeasures
 - Ensure `lodash` version `4.17.12+` is used with safer `merge` and `extend` functions.
 - Avoid using `defaultsDeep`, since the function can lead to object mutation.
 ## Additional information
 **[CWE-89](https://cwe.mitre.org/data/definitions/89.html)**
 **[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
 **[Javascript Object prototypes](https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Objects/Object_prototypes)**
-------------------------------------
 _______________________________________________________________________________________________
 | tracked                    | lineNumber| method               | file                         |
 |==============================================================================================|
 | req                        | 12        | check                | vulnerabilities/dep-lodash.js|
 | req.body.config            | 14        | check                | vulnerabilities/dep-lodash.js|
 | p1                         | N/A       | JSON.parse           |                              |
 | ret                        | N/A       | JSON.parse           |                              |
 | JSON.parse(req.body.config)| 14        | check                | vulnerabilities/dep-lodash.js|
 | p2                         | N/A       | ^lodash^.defaultsDeep|                              |


------------------------------------
Title: Sensitive Data Leak: Sensitive data is leaked via `req` to log in `anonymous`
Score: 8.0
Categories: [a3-sensitive-data-exposure]
Flow ids: [4355481239626404686]
Description: Sensitive data leak detected in this flow. This data may be visible to a third party that has access to the logs, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.


## Countermeasures

This vulnerability can be prevented by not writing sensitive data to the log or by encrypting it in advance.

## Additional information

**[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**

**[CWE-117](https://cwe.mitre.org/data/definitions/117.html)**

**[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**
-------------------------------------
 _______________________________________________________________________________________
 | tracked            | lineNumber| method                | file                        |
 |======================================================================================|
 | req                | 6         | anonymous             | vulnerabilities/sensitive.js|
 | req.query          | 7         | anonymous             | vulnerabilities/sensitive.js|
 | p2                 | N/A       | <operator>.assignment |                             |
 | p1                 | N/A       | <operator>.assignment |                             |
 | _req$query         | 7         | anonymous             | vulnerabilities/sensitive.js|
 | _req$query.password| 9         | anonymous             | vulnerabilities/sensitive.js|
 | p2                 | N/A       | <operator>.assignment |                             |
 | p1                 | N/A       | <operator>.assignment |                             |
 | password           | 9         | anonymous             | vulnerabilities/sensitive.js|
 | password           | 10        | anonymous             | vulnerabilities/sensitive.js|
 | p1                 | N/A       | ^__whatwg.console^.log|                             |


------------------------------------
Title: Sensitive Data Leak: Sensitive data is leaked to log in `anonymous`
Score: 8.0
Categories: [a3-sensitive-data-exposure]
Flow ids: [4355481239626404666]
Description: Sensitive data leak detected in this flow. This data may be visible to a third party that has access to the logs, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.


## Countermeasures

This vulnerability can be prevented by not writing sensitive data to the log or by encrypting it in advance.

## Additional information

**[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**

**[CWE-117](https://cwe.mitre.org/data/definitions/117.html)**

**[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**
-------------------------------------
 ____________________________________________________________________________
 | tracked | lineNumber| method                | file                        |
 |===========================================================================|
 | password| 9         | anonymous             | vulnerabilities/sensitive.js|
 | password| 10        | anonymous             | vulnerabilities/sensitive.js|
 | p1      | N/A       | ^__whatwg.console^.log|                             |


------------------------------------
Title: Sensitive Data Leak: Sensitive data is leaked via `req` to log in `anonymous2`
Score: 8.0
Categories: [a3-sensitive-data-exposure]
Flow ids: [4355481239626404730]
Description: Sensitive data leak detected in this flow. This data may be visible to a third party that has access to the logs, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.


## Countermeasures

This vulnerability can be prevented by not writing sensitive data to the log or by encrypting it in advance.

## Additional information

**[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**

**[CWE-117](https://cwe.mitre.org/data/definitions/117.html)**

**[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**
-------------------------------------
 ________________________________________________________________________________________
 | tracked             | lineNumber| method                | file                        |
 |=======================================================================================|
 | req                 | 20        | anonymous2            | vulnerabilities/sensitive.js|
 | req.query           | 21        | anonymous2            | vulnerabilities/sensitive.js|
 | p2                  | N/A       | <operator>.assignment |                             |
 | p1                  | N/A       | <operator>.assignment |                             |
 | _req$query2         | 21        | anonymous2            | vulnerabilities/sensitive.js|
 | _req$query2.username| 22        | anonymous2            | vulnerabilities/sensitive.js|
 | p2                  | N/A       | <operator>.assignment |                             |
 | p1                  | N/A       | <operator>.assignment |                             |
 | username            | 22        | anonymous2            | vulnerabilities/sensitive.js|
 | username            | 27        | anonymous2            | vulnerabilities/sensitive.js|
 | p2                  | N/A       | <operator>.assignment |                             |
 | p1                  | N/A       | <operator>.assignment |                             |
 | data.username       | 27        | anonymous2            | vulnerabilities/sensitive.js|
 | data                | 31        | anonymous2            | vulnerabilities/sensitive.js|
 | p1                  | N/A       | ^__whatwg.console^.log|                             |


------------------------------------
Title: Sensitive Data Leak: Sensitive data is leaked to log in `anonymous2`
Score: 8.0
Categories: [a3-sensitive-data-exposure]
Flow ids: [4355481239626404706]
Description: Sensitive data leak detected in this flow. This data may be visible to a third party that has access to the logs, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.


## Countermeasures

This vulnerability can be prevented by not writing sensitive data to the log or by encrypting it in advance.

## Additional information

**[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**

**[CWE-117](https://cwe.mitre.org/data/definitions/117.html)**

**[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**
-------------------------------------
 _________________________________________________________________________________
 | tracked      | lineNumber| method                | file                        |
 |================================================================================|
 | password     | 23        | anonymous2            | vulnerabilities/sensitive.js|
 | password     | 28        | anonymous2            | vulnerabilities/sensitive.js|
 | p2           | N/A       | <operator>.assignment |                             |
 | p1           | N/A       | <operator>.assignment |                             |
 | data.password| 28        | anonymous2            | vulnerabilities/sensitive.js|
 | data         | 31        | anonymous2            | vulnerabilities/sensitive.js|
 | p1           | N/A       | ^__whatwg.console^.log|                             |


------------------------------------
Title: Sensitive Data Leak: Sensitive data is leaked via `req` to log in `anonymous2`
Score: 8.0
Categories: [a3-sensitive-data-exposure]
Flow ids: [4355481239626404754]
Description: Sensitive data leak detected in this flow. This data may be visible to a third party that has access to the logs, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.


## Countermeasures

This vulnerability can be prevented by not writing sensitive data to the log or by encrypting it in advance.

## Additional information

**[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**

**[CWE-117](https://cwe.mitre.org/data/definitions/117.html)**

**[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**
-------------------------------------
 ________________________________________________________________________________________
 | tracked             | lineNumber| method                | file                        |
 |=======================================================================================|
 | req                 | 20        | anonymous2            | vulnerabilities/sensitive.js|
 | req.query           | 21        | anonymous2            | vulnerabilities/sensitive.js|
 | p2                  | N/A       | <operator>.assignment |                             |
 | p1                  | N/A       | <operator>.assignment |                             |
 | _req$query2         | 21        | anonymous2            | vulnerabilities/sensitive.js|
 | _req$query2.password| 23        | anonymous2            | vulnerabilities/sensitive.js|
 | p2                  | N/A       | <operator>.assignment |                             |
 | p1                  | N/A       | <operator>.assignment |                             |
 | password            | 23        | anonymous2            | vulnerabilities/sensitive.js|
 | password            | 28        | anonymous2            | vulnerabilities/sensitive.js|
 | p2                  | N/A       | <operator>.assignment |                             |
 | p1                  | N/A       | <operator>.assignment |                             |
 | data.password       | 28        | anonymous2            | vulnerabilities/sensitive.js|
 | data                | 31        | anonymous2            | vulnerabilities/sensitive.js|
 | p1                  | N/A       | ^__whatwg.console^.log|                             |


------------------------------------
Title: Sensitive Data Leak: Sensitive data is leaked to log in `anonymous2`
Score: 8.0
Categories: [a3-sensitive-data-exposure]
Flow ids: [4355481239626404718]
Description: Sensitive data leak detected in this flow. This data may be visible to a third party that has access to the logs, such as system administrators. Many web applications and APIs do not protect sensitive data, such as financial and healthcare. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.


## Countermeasures

This vulnerability can be prevented by not writing sensitive data to the log or by encrypting it in advance.

## Additional information

**[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**

**[CWE-117](https://cwe.mitre.org/data/definitions/117.html)**

**[OWASP-A3](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)**
-------------------------------------
 _________________________________________________________________________________
 | tracked      | lineNumber| method                | file                        |
 |================================================================================|
 | username     | 22        | anonymous2            | vulnerabilities/sensitive.js|
 | username     | 27        | anonymous2            | vulnerabilities/sensitive.js|
 | p2           | N/A       | <operator>.assignment |                             |
 | p1           | N/A       | <operator>.assignment |                             |
 | data.username| 27        | anonymous2            | vulnerabilities/sensitive.js|
 | data         | 31        | anonymous2            | vulnerabilities/sensitive.js|
 | p1           | N/A       | ^__whatwg.console^.log|                             |


------------------------------------
Title: XSS: HTTP data to HTML via `req` in `anonymous1`
Score: 8.0
Categories: [a7-XSS]
Flow ids: [4355481239626404880]
Description: Data from HTTP request parameters is used in HTML or session information. Unless the string is validated, this may result in a XSS attack.


## Countermeasures

This vulnerability can be prevented by using input sanitization/validation techniques (e.g., whitelisting) on the HTTP data before using it inside another HTTP header.

## Additional information

**[CWE-79](https://cwe.mitre.org/data/definitions/79.html)**

**[OWASP-A7](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS))**
-------------------------------------
 __________________________________________________________________________________________
 | tracked                  | lineNumber| method                   | file                  |
 |=========================================================================================|
 | req                      | 10        | anonymous1               | vulnerabilities/xss.js|
 | req.query.name           | 11        | anonymous1               | vulnerabilities/xss.js|
 | p2                       | N/A       | <operator>.assignment    |                       |
 | p1                       | N/A       | <operator>.assignment    |                       |
 | name                     | 11        | anonymous1               | vulnerabilities/xss.js|
 | name                     | 13        | anonymous1               | vulnerabilities/xss.js|
 | p2                       | N/A       | <operator>.assignment    |                       |
 | p1                       | N/A       | <operator>.assignment    |                       |
 | _tmp_0.user_name         | 13        | anonymous1               | vulnerabilities/xss.js|
 | {
    user_name: name
  }| 12        | anonymous1               | vulnerabilities/xss.js|
 | p2                       | N/A       | ^express.Response^.render|                       |


------------------------------------
Title: SQL Injection: HTTP data to SQL database via `req` in `anonymous`
Score: 9.0
Categories: [a1-injection]
Flow ids: [4355481239626404646]
Description: HTTP data is used in a SQL query without undergoing escaping or validation. This could allow an attacker to read sensitive data from the database, modify its content or gain control over the server.


## Countermeasures

This vulnerability can be prevented by using prepared statements on the HTTP data.

## Additional information

**[CWE-89](https://cwe.mitre.org/data/definitions/89.html)**

**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 ________________________________________________________________________________________________________
 | tracked                                 | lineNumber| method                 | file                   |
 |=======================================================================================================|
 | req                                     | 19        | anonymous              | vulnerabilities/sqli.js|
 | req.params.id                           | 20        | anonymous              | vulnerabilities/sqli.js|
 | p2                                      | N/A       | <operator>.assignment  |                        |
 | p1                                      | N/A       | <operator>.assignment  |                        |
 | userId                                  | 20        | anonymous              | vulnerabilities/sqli.js|
 | userId                                  | 21        | anonymous              | vulnerabilities/sqli.js|
 | p2                                      | N/A       | <operator>.addition    |                        |
 | ret                                     | N/A       | <operator>.addition    |                        |
 | "SELECT * FROM users WHERE id=" + userId| 21        | anonymous              | vulnerabilities/sqli.js|
 | p1                                      | N/A       | ^MysqlConnection^.query|                        |


------------------------------------
Title: Remote Code Execution: Command Injection through HTTP via `ctx` in `anonymous`
Score: 9.0
Categories: [a1-injection]
Flow ids: [4355481239626404808]
Description: HTTP data is used in a shell command without undergoing escaping or validation. This could allow an attacker to execute code on the server. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. By injecting hostile data, an attacker may trick the interpreter into executing unintended commands or accessing data without authorization which can result in data loss, corruption, or disclosure to unauthorized parties, loss of accountability, denial of access or even a complete host takeover.


## Countermeasures

This vulnerability can be prevented by using parameterized queries or by validating HTTP data (preferably on server-side by means of common input sanitation libraries or whitelisting) before using it.

## Additional information

**[CWE-77](https://cwe.mitre.org/data/definitions/77.html)**

**[CWE-78](https://cwe.mitre.org/data/definitions/78.html)**

**[CWE-917](https://cwe.mitre.org/data/definitions/917.html)**

**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 _______________________________________________________________________________
 | tracked       | lineNumber| method               | file                      |
 |==============================================================================|
 | ctx           | 13        | anonymous            | vulnerabilities/koa-rce.js|
 | ctx.params.cmd| 14        | anonymous            | vulnerabilities/koa-rce.js|
 | p2            | N/A       | <operator>.assignment|                           |
 | p1            | N/A       | <operator>.assignment|                           |
 | cmd           | 14        | anonymous            | vulnerabilities/koa-rce.js|
 | cmd           | 15        | anonymous            | vulnerabilities/koa-rce.js|
 | p1            | N/A       | ^execa^.sync         |                           |


------------------------------------
Title: Remote Code Execution: Command Injection through HTTP via `req` in `anonymous`
Score: 9.0
Categories: [a1-injection]
Flow ids: [4355481239626404778]
Description: HTTP data is used in a shell command without undergoing escaping or validation. This could allow an attacker to execute code on the server. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. By injecting hostile data, an attacker may trick the interpreter into executing unintended commands or accessing data without authorization which can result in data loss, corruption, or disclosure to unauthorized parties, loss of accountability, denial of access or even a complete host takeover.


## Countermeasures

This vulnerability can be prevented by using parameterized queries or by validating HTTP data (preferably on server-side by means of common input sanitation libraries or whitelisting) before using it.

## Additional information

**[CWE-77](https://cwe.mitre.org/data/definitions/77.html)**

**[CWE-78](https://cwe.mitre.org/data/definitions/78.html)**

**[CWE-917](https://cwe.mitre.org/data/definitions/917.html)**

**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 _________________________________________________________________________
 | tracked     | lineNumber| method              | file                   |
 |========================================================================|
 | req         | 13        | anonymous           | vulnerabilities/exec.js|
 | req.body.url| 14        | anonymous           | vulnerabilities/exec.js|
 | p1          | N/A       | ^child_process^.exec|                        |


------------------------------------
Title: Remote Code Execution: Command Injection through HTTP via `req` in `anonymous2`
Score: 9.0
Categories: [a1-injection]
Flow ids: [4355481239626404790]
Description: HTTP data is used in a shell command without undergoing escaping or validation. This could allow an attacker to execute code on the server. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. By injecting hostile data, an attacker may trick the interpreter into executing unintended commands or accessing data without authorization which can result in data loss, corruption, or disclosure to unauthorized parties, loss of accountability, denial of access or even a complete host takeover.


## Countermeasures

This vulnerability can be prevented by using parameterized queries or by validating HTTP data (preferably on server-side by means of common input sanitation libraries or whitelisting) before using it.

## Additional information

**[CWE-77](https://cwe.mitre.org/data/definitions/77.html)**

**[CWE-78](https://cwe.mitre.org/data/definitions/78.html)**

**[CWE-917](https://cwe.mitre.org/data/definitions/917.html)**

**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 ____________________________________________________________________________
 | tracked       | lineNumber| method               | file                   |
 |===========================================================================|
 | req           | 29        | anonymous2           | vulnerabilities/exec.js|
 | req.params.cmd| 30        | anonymous2           | vulnerabilities/exec.js|
 | p2            | N/A       | <operator>.assignment|                        |
 | p1            | N/A       | <operator>.assignment|                        |
 | cmd           | 30        | anonymous2           | vulnerabilities/exec.js|
 | cmd           | 31        | anonymous2           | vulnerabilities/exec.js|
 | cmd           | 34        | runMe                | vulnerabilities/exec.js|
 | cmd           | 36        | runMe                | vulnerabilities/exec.js|
 | p1            | N/A       | ^child_process^.spawn|                        |


------------------------------------
Title: Remote Code Execution: Command Injection through HTTP via `req` in `anonymous3`
Score: 9.0
Categories: [a1-injection]
Flow ids: [4355481239626404824]
Description: HTTP data is used in a shell command without undergoing escaping or validation. This could allow an attacker to execute code on the server. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. By injecting hostile data, an attacker may trick the interpreter into executing unintended commands or accessing data without authorization which can result in data loss, corruption, or disclosure to unauthorized parties, loss of accountability, denial of access or even a complete host takeover.


## Countermeasures

This vulnerability can be prevented by using parameterized queries or by validating HTTP data (preferably on server-side by means of common input sanitation libraries or whitelisting) before using it.

## Additional information

**[CWE-77](https://cwe.mitre.org/data/definitions/77.html)**

**[CWE-78](https://cwe.mitre.org/data/definitions/78.html)**

**[CWE-917](https://cwe.mitre.org/data/definitions/917.html)**

**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 ____________________________________________________________________________
 | tracked       | lineNumber| method               | file                   |
 |===========================================================================|
 | req           | 42        | anonymous3           | vulnerabilities/exec.js|
 | req.params.cmd| 43        | anonymous3           | vulnerabilities/exec.js|
 | p2            | N/A       | <operator>.assignment|                        |
 | p1            | N/A       | <operator>.assignment|                        |
 | cmd           | 43        | anonymous3           | vulnerabilities/exec.js|
 | cmd           | 44        | anonymous3           | vulnerabilities/exec.js|
 | p1            | N/A       | ^execa^.sync         |                        |


------------------------------------
Title: XXE: HTTP data to XML via `req` in `anonymous`
Score: 9.0
Categories: [A4-XXE]
Flow ids: [4355481239626405076]
Description: This flow indicates an XXE attack. An attacker could read arbitrary files, if the features are not disabled.


## Countermeasures

This vulnerability can be prevented by disabling XML External Entity for server-side XML parser altogether. You can find more information in the [OWASP (XXE) Prevention Cheat Sheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).

## Additional information

- **[CWE-611](https://cwe.mitre.org/data/definitions/611.html)**

- **[OWASP-A4](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A4-XML_External_Entities_(XXE))**
-------------------------------------
 ______________________________________________________________________________________
 | tracked                | lineNumber| method                 | file                  |
 |=====================================================================================|
 | req                    | 10        | anonymous              | vulnerabilities/xxe.js|
 | req.files.products.data| 11        | anonymous              | vulnerabilities/xxe.js|
 | p2                     | N/A       | <operator>.assignment  |                       |
 | p1                     | N/A       | <operator>.assignment  |                       |
 | XMLfile                | 11        | anonymous              | vulnerabilities/xxe.js|
 | XMLfile                | 12        | anonymous              | vulnerabilities/xxe.js|
 | p1                     | N/A       | ^libxml^.parseXmlString|                       |


------------------------------------
Title: Remote Code Execution: Command Injection through HTTP via `ctx` in `anonymous`
Score: 9.0
Categories: [a1-injection]
Flow ids: [4355481239626404808]
Description: HTTP data is used in a shell command without undergoing escaping or validation. This could allow an attacker to execute code on the server. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. By injecting hostile data, an attacker may trick the interpreter into executing unintended commands or accessing data without authorization which can result in data loss, corruption, or disclosure to unauthorized parties, loss of accountability, denial of access or even a complete host takeover.


## Countermeasures

This vulnerability can be prevented by using parameterized queries or by validating HTTP data (preferably on server-side by means of common input sanitation libraries or whitelisting) before using it.

## Additional information

**[CWE-77](https://cwe.mitre.org/data/definitions/77.html)**

**[CWE-78](https://cwe.mitre.org/data/definitions/78.html)**

**[CWE-917](https://cwe.mitre.org/data/definitions/917.html)**

**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 _______________________________________________________________________________
 | tracked       | lineNumber| method               | file                      |
 |==============================================================================|
 | ctx           | 13        | anonymous            | vulnerabilities/koa-rce.js|
 | ctx.params.cmd| 14        | anonymous            | vulnerabilities/koa-rce.js|
 | p2            | N/A       | <operator>.assignment|                           |
 | p1            | N/A       | <operator>.assignment|                           |
 | cmd           | 14        | anonymous            | vulnerabilities/koa-rce.js|
 | cmd           | 15        | anonymous            | vulnerabilities/koa-rce.js|
 | p1            | N/A       | ^execa^.sync         |                           |


------------------------------------
Title: Remote Code Execution: Command Injection through HTTP via `req` in `anonymous`
Score: 9.0
Categories: [a1-injection]
Flow ids: [4355481239626404778]
Description: HTTP data is used in a shell command without undergoing escaping or validation. This could allow an attacker to execute code on the server. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. By injecting hostile data, an attacker may trick the interpreter into executing unintended commands or accessing data without authorization which can result in data loss, corruption, or disclosure to unauthorized parties, loss of accountability, denial of access or even a complete host takeover.


## Countermeasures

This vulnerability can be prevented by using parameterized queries or by validating HTTP data (preferably on server-side by means of common input sanitation libraries or whitelisting) before using it.

## Additional information

**[CWE-77](https://cwe.mitre.org/data/definitions/77.html)**

**[CWE-78](https://cwe.mitre.org/data/definitions/78.html)**

**[CWE-917](https://cwe.mitre.org/data/definitions/917.html)**

**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 _________________________________________________________________________
 | tracked     | lineNumber| method              | file                   |
 |========================================================================|
 | req         | 13        | anonymous           | vulnerabilities/exec.js|
 | req.body.url| 14        | anonymous           | vulnerabilities/exec.js|
 | p1          | N/A       | ^child_process^.exec|                        |


------------------------------------
Title: Remote Code Execution: Command Injection through HTTP via `req` in `anonymous2`
Score: 9.0
Categories: [a1-injection]
Flow ids: [4355481239626404790]
Description: HTTP data is used in a shell command without undergoing escaping or validation. This could allow an attacker to execute code on the server. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. By injecting hostile data, an attacker may trick the interpreter into executing unintended commands or accessing data without authorization which can result in data loss, corruption, or disclosure to unauthorized parties, loss of accountability, denial of access or even a complete host takeover.


## Countermeasures

This vulnerability can be prevented by using parameterized queries or by validating HTTP data (preferably on server-side by means of common input sanitation libraries or whitelisting) before using it.

## Additional information

**[CWE-77](https://cwe.mitre.org/data/definitions/77.html)**

**[CWE-78](https://cwe.mitre.org/data/definitions/78.html)**

**[CWE-917](https://cwe.mitre.org/data/definitions/917.html)**

**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 ____________________________________________________________________________
 | tracked       | lineNumber| method               | file                   |
 |===========================================================================|
 | req           | 29        | anonymous2           | vulnerabilities/exec.js|
 | req.params.cmd| 30        | anonymous2           | vulnerabilities/exec.js|
 | p2            | N/A       | <operator>.assignment|                        |
 | p1            | N/A       | <operator>.assignment|                        |
 | cmd           | 30        | anonymous2           | vulnerabilities/exec.js|
 | cmd           | 31        | anonymous2           | vulnerabilities/exec.js|
 | cmd           | 34        | runMe                | vulnerabilities/exec.js|
 | cmd           | 36        | runMe                | vulnerabilities/exec.js|
 | p1            | N/A       | ^child_process^.spawn|                        |


------------------------------------
Title: Remote Code Execution: Command Injection through HTTP via `req` in `anonymous3`
Score: 9.0
Categories: [a1-injection]
Flow ids: [4355481239626404824]
Description: HTTP data is used in a shell command without undergoing escaping or validation. This could allow an attacker to execute code on the server. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. By injecting hostile data, an attacker may trick the interpreter into executing unintended commands or accessing data without authorization which can result in data loss, corruption, or disclosure to unauthorized parties, loss of accountability, denial of access or even a complete host takeover.


## Countermeasures

This vulnerability can be prevented by using parameterized queries or by validating HTTP data (preferably on server-side by means of common input sanitation libraries or whitelisting) before using it.

## Additional information

**[CWE-77](https://cwe.mitre.org/data/definitions/77.html)**

**[CWE-78](https://cwe.mitre.org/data/definitions/78.html)**

**[CWE-917](https://cwe.mitre.org/data/definitions/917.html)**

**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 ____________________________________________________________________________
 | tracked       | lineNumber| method               | file                   |
 |===========================================================================|
 | req           | 42        | anonymous3           | vulnerabilities/exec.js|
 | req.params.cmd| 43        | anonymous3           | vulnerabilities/exec.js|
 | p2            | N/A       | <operator>.assignment|                        |
 | p1            | N/A       | <operator>.assignment|                        |
 | cmd           | 43        | anonymous3           | vulnerabilities/exec.js|
 | cmd           | 44        | anonymous3           | vulnerabilities/exec.js|
 | p1            | N/A       | ^execa^.sync         |                        |


------------------------------------
Title: SQL Injection: HTTP data to SQL database via `req` in `anonymous`
Score: 9.0
Categories: [a1-injection]
Flow ids: [4355481239626404646]
Description: HTTP data is used in a SQL query without undergoing escaping or validation. This could allow an attacker to read sensitive data from the database, modify its content or gain control over the server.


## Countermeasures

This vulnerability can be prevented by using prepared statements on the HTTP data.

## Additional information

**[CWE-89](https://cwe.mitre.org/data/definitions/89.html)**

**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**
-------------------------------------
 ________________________________________________________________________________________________________
 | tracked                                 | lineNumber| method                 | file                   |
 |=======================================================================================================|
 | req                                     | 19        | anonymous              | vulnerabilities/sqli.js|
 | req.params.id                           | 20        | anonymous              | vulnerabilities/sqli.js|
 | p2                                      | N/A       | <operator>.assignment  |                        |
 | p1                                      | N/A       | <operator>.assignment  |                        |
 | userId                                  | 20        | anonymous              | vulnerabilities/sqli.js|
 | userId                                  | 21        | anonymous              | vulnerabilities/sqli.js|
 | p2                                      | N/A       | <operator>.addition    |                        |
 | ret                                     | N/A       | <operator>.addition    |                        |
 | "SELECT * FROM users WHERE id=" + userId| 21        | anonymous              | vulnerabilities/sqli.js|
 | p1                                      | N/A       | ^MysqlConnection^.query|                        |

