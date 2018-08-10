# McAfee ESM Virustotal
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This small guide provides the ability to run live Virustotal lookups based on Hashes or IP’s from the McAfee ESM right click actions menu.

The script will lookup Virustotal and ingest the response in McAfee ESM via Syslog CEF.

## Step 1

Open the virustotal.py script and change the Syslog Server IP in line 9 and the Virustotal API key in line 12.

<img width="596" alt="screen shot 2018-08-10 at 11 32 39" src="https://user-images.githubusercontent.com/25227268/43950635-23ae8a5e-9c91-11e8-9c2c-8e82287701cd.png">

Put the script on a system that has python installed and is accessible from the McAfee ESM.
You can use the script by executing the following.

```
For ip lookup: 
python virustotal.py ip 5.79.68.161
 
For hash lookup:
python virustotal.py hash 20d2c5f683fc5e2aafc5895968cd7e6d
```

## Step 2
Add a new data source to your receiver. Make sure you enter the IP of the system where the script is located.

<img width="596" alt="screen shot 2018-08-10 at 11 36 04" src="https://user-images.githubusercontent.com/25227268/43950781-9aefb606-9c91-11e8-84f0-3a4fe7b4421a.png">

## Step 3
In ESM open the Configuration > Profile Management > Remote Commands. Add a new remote command like the following. (Repeat the same procedure for the IP lookup)

<img width="416" alt="screen shot 2018-08-10 at 11 37 44" src="https://user-images.githubusercontent.com/25227268/43950853-d5c6fca8-9c91-11e8-9131-3f72cbd07ca9.png">

## Step 4
Import the attached ASP (virustotal_hash_lookup.xml and virustotal_ip_lookup.xml) rules (to parse the CEF syslog message from the script). Make sure you enable the imported rules for your data source (created in step 2).

## Step 5
Go to Data Sources and disable aggregation for the two imported rules.

<img width="1018" alt="screen shot 2018-08-10 at 11 41 23" src="https://user-images.githubusercontent.com/25227268/43951041-54d67046-9c92-11e8-972b-91eb05030eeb.png">

## Step 6
Now you can use either right click > Action > Virustotal Hash Lookup or you use an alarm to execute the remote command.

<img width="1440" alt="screen shot 2018-08-10 at 11 42 57" src="https://user-images.githubusercontent.com/25227268/43951132-8eed4bf6-9c92-11e8-81d8-3ea5c3bed0f2.png">

<img width="1440" alt="screen shot 2018-08-10 at 11 43 46" src="https://user-images.githubusercontent.com/25227268/43951158-abcc73c8-9c92-11e8-953b-cce14f2e067a.png">

