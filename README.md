# cis-benchmark-centOS-8
Auditing Script based on CIS-BENCHMARK CENTOS 8 v1.0.0


## INSTRUCTION
#### Download:

     git clone https://github.com/mrC2C/cis-benchmark-centOS-8.git
     
#### Permission granted to the script:
     chmod 750 cis-benchmark-centOS-8/centOS8.sh
     
#### Options:
     OPTIONS: 
        -h,     --help          Display the help message
        -ls,    --list
        -l,     --level         Indicate the level 1 or 2 for server/workstation to audit
        -e,     --exclude       Indicate the level and categories id to be excluded from auditingi. 
                                FORMAT: LEVEL.CAT_ID meaning level first followed by categories id
                                e.g. 1.1.1  ==> meaning exclude level 1 and categories id 1.1 
        -vv,    --verbose       Display the debug file, while the script is running
        -sh,	--show		Display results from the json file 

     EXAMPLE:
       sudo ./centOS8.sh -e 1.1.1,2.1.1 -vv    #Execute the script to audit for both LEVEL 1 & 2 but exclude categories id 1.1
       sudo ./centOS8.sh -l 1 -e 1.2.1,1.6.1 -vv
       sudo ./centOS8.sh -l 2 -e 2.1.1, 2.3.1 -vv
       sudo ./centOS8.sh -vv -sh               #Execute the script to audit for both LEVELs and display the results
        
#### Run:
      cd cis-benchmark-centOS-8/
      sudo ./centOS8.sh -vv       #If you want to run everything in verbose mode
      
#### Log Directory:
     /var/log/centOS8_audit
     |_____ debug        #debug file
     |_____ json_log     #Go to this directory, if you want to see the results. It is formatted into a json file.
     
#### How the function display the result from the json file?
     In the json file,
     audit
     |____ level
     |____ chapters (for e.g. "one")
           |________ categories (for e.g. 1.1) => the function will display results of its no. of pass, fail and null. 
                     |___________ sub-categories (for e.g. id 1.1.1)
     
     For example, its output will be
      
     LEVEL 1
     =========
     Chp one
     =========
	     --   -----------                    ----  ----  ----
	     ID   Description                    Pass  Fail  Null
	     --   -----------                    ----  ----  ----
	     1.1  filesystem configuration       3     6     3
	     1.2  software updates               1     0     2
	     1.3  sudo                           1     2     0
	     1.4  filesystem integrity checking  1     1     0
	     1.5  secure boot settings           1     2     0
	     1.6  additional process hardening   1     1     0
	     1.7  warning banners                2     3     1

## Note:
Hi all, this is my first time creating a project on GITHUB. Since, this is my first time doing such project, I would like to ask you guys to help me check it out. Feel free to send feedback on what to improve on or add any new features.
 
Do note that function 'no_exist' will take a while due to the number of checks it need to process. 

If you like the script, do leave a star :)
 
## UPDATES:
#### What's New?
Added a new function to display results from the json file.

#### What's Next?
I m looking for contributors to enrich and enhance this project, to ensure the script is more effective.

#### Update 1.0.1.0
Added new function to display results from json file. 
 
