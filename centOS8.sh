#! /usr/bin/env bash

## GLOBAL VARIABLES ##
args=$@
exit_code=0
tos=1 ## TIME TO SLEEP
all=0

chp="" # chapter
catid="" # categories id
level=0
result=Fail

declare -a excl_arr1
declare -a excl_arr2

## DECLARING THE DIRECTORIES ##
LOG_DIR="/var/log/centOS8_audit"
sub_logdir="$LOG_DIR/json_log"
debug_dir="/var/log/centOS8_audit/debug"
debug_file="centos_debug.log"
debug_dir="/var/log/centOS8_audit/debug"
JSN_DIR="json_file"
JSN_FIL="centOS8.json"
bannerfile="banner.txt"

		###	DISPLAY FEATURES      ###
function banner()
{
	cat ${bannerfile}

}

		###	WRITE FUNCTION	  ###
function write_result()
{
	local level chp catg ids res
	level=$1
	chp=$2
	catid=$3
	ids=$4
	res=$5

	#Retrieve result from json file
	oldval=$(jq -c --arg level ${level} --arg chp ${chp} --arg catid ${catid} --arg id ${ids}  ".audit[] | select(.level==$level) | .chapters[\"$chp\"].categories[] | select(.id==$catid) | .report[] | select(.id==\"$id\")" "$JSN_DIR/$JSN_FIL")

	newval=$(jq -c --arg level ${level} --arg chp ${chp} --arg catid ${catid} --arg id ${ids} --arg result ${res} ".audit[] | select(.level==$level) | .chapters[\"$chp\"].categories[] | select(.id==$catid) | .report[] | select(.id==\"$id\") | .result=\"$result\"" "$JSN_DIR/$JSN_FIL")

	#Update the json_file with new value 
	sed -i "s@${oldval}@${newval}@" "$JSN_DIR/$JSN_FIL"

}

function write_info()
{
	if [ verbose ]; then
		echo "$(date -Ins) [INFO] $@" | tee -a "$debug_dir/$debug_file"
	else
		echo "$(date -Ins) [INFO] $@" >> "$debug_dir/$debug_file"
	fi
}

function write_debug()
{
	if [ verbose ]; then
		echo "$(date -Ins) [DEBUG] $@" | tee -a "$debug_dir/$debug_file"
	else
		echo "$(date -Ins) [DEBUG] $@" >> "$debug_dir/$debug_file" 
	fi
}

		###	Renaming LOG FILE	###
function rename()
{
	local TMP_DIR TMP_FILE
	TMP_DIR=$1
	TMP_FILE=$2

	#RENAME LOG FILE by adding timestamp to it
	NEW_FIL="${TMP_FILE}.$(date "+%Y%m%d_%H%M%S")"

	mv "${TMP_DIR}/${TMP_FILE}" "${TMP_DIR}/${NEW_FIL}"

	mv "${TMP_DIR}/${NEW_FIL}" "${sub_logdir}/${NEW_FIL}"	

}

		###	  DEFINE FUNCTIONS	###

## USAGE FUNCTION ##
function usage()
{
        cat << EOF
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
        sudo ./centOS8.sh -e 1.1.1,2.1.1 -vv    #Execute the script to audit both LEVEL 1 & 2 but exclude categories id 1.1
        sudo ./centOS8.sh -l 1 -e 1.2.1,1.6.1 -vv 
        sudo ./centOS8.sh -l 2 -e 2.1.1, 2.3.1 -vv

EOF
}

function display()
{
	cat << EOF
CentOS 8 Auditing Scripts
Level 1:
	Chapter 1:
	||
	========> Categories ID  |	Name
		  -------------------------------------------
		  1.1		 |  FILESYSTEM CONFIGURATION
		  -------------------------------------------
		  1.2		 |  SOFTWARE UPDATES
		  -------------------------------------------
		  1.3		 |  SUDO
		  -------------------------------------------
		  1.4		 |  FILESYSTEM INTEGRITY 
				 |  CHECK
		  -------------------------------------------
		  1.5 		 |  SECURE BOOT SETTINGS
		  -------------------------------------------
		  1.6		 |  ADDITIONAL PROCESS
				 |  HARDENING
		  -------------------------------------------
		  1.7		 |  WARNING BANNERS
		  -------------------------------------------

	Chapter 2:
	||
	========> Categories ID  |  	Name
		  -------------------------------------------
		  2.1		 |  INETD SERVICE
		  -------------------------------------------
		  2.2		 |  TIME SYNCHRONIZATION
		  -------------------------------------------
		  2.3		 |  SPECIAL PURPOSE SERVICES
		  -------------------------------------------
		  2.4		 |  SERVICE CLIENTS
		  -------------------------------------------
	
	Chapter 3:
	||
	========> Categories ID  | 	Name
		  -------------------------------------------
		  3.1		 |  NETWORK PARAMETER (host only)
		  -------------------------------------------
		  3.2		 |  NETWORK PARAMETER (host and router)
		  -------------------------------------------
		  3.3		 |  FIREWALL CONFIGURATION
		  -------------------------------------------
		  3.4		 |  WIRELESS INTERFACES
		  -------------------------------------------

	Chapter 4:
	||
	========> Categories ID  | 	Name
		  -------------------------------------------
		  4.1		 |  CONFIGURE LOGGING
		  -------------------------------------------
		  4.2		 |  LOG ROTATION
		  -------------------------------------------

	Chapter 5:
	||
	========> Categories ID  | 	Name
		  -------------------------------------------
		  5.1		 |  CONFIGURE CRON
		  -------------------------------------------
		  5.2		 |  SSH SERVER CONFIGURATION
		  -------------------------------------------
		  5.3		 |  CONFIGURE AUTHSELECT
		  -------------------------------------------
		  5.4		 |  CONFIGURE PAM
		  -------------------------------------------
		  5.5		 |  USER ACCOUNTS &
				 |  Environment
		  -------------------------------------------
		  5.6		 |  ROOT LOGIN CONFIGURATION
		  -------------------------------------------
		  5.7		 |  SU COMMAND
		  -------------------------------------------

	Chapter 6:
	||
	========> Categories ID  | 	Name
		  -------------------------------------------
		  6.1		 |  SYSTEM FILE PERMISSIONS
		  -------------------------------------------
		  6.2		 |  USER & GROUP SETTINGS
		  -------------------------------------------


Level 2:
	Chapter 1:
	||
	========> Categories ID  | 	Name
		  -------------------------------------------
		  1.1		 |  FILESYSTEM CONFIGURATION
		  -------------------------------------------
		  1.2		 |  MANDATORY ACCESS CONTROL
		  -------------------------------------------
		  1.3		 |  WARNING BANNERS
		  -------------------------------------------

	Chapter 3:
	||
	========> Categories ID  | 	Name
		  -------------------------------------------
		  3.1		 |  UNCOMMON NETWORK PROTOCOL
		  -------------------------------------------
		  3.2		 |  WIRELESS CONFIGURATION
		  -------------------------------------------
		  3.3		 |  DISABLE IPv6
		  -------------------------------------------

	Chapter 4:
	||
	========> Categories ID  | 	Name
		  -------------------------------------------
		  4.1		 |  CONFIGURE SYSTEM
				 |  ACCOUNTING
		  -------------------------------------------

	Chapter 5:
	||
	========> Categories ID  | 	Name
		  -------------------------------------------
		  5.1		 |  SSH SERVER CONFIGURATION
		  -------------------------------------------

	Chapter 6:
	||
	========> Categories ID  | 	Name
		  -------------------------------------------
		  6.1		 |  SYSTEM FILE PERMISSIONS
		  -------------------------------------------

EOF
}
	

function run_test()
{
	local args level funct id
	args=$($@)
	funct=$1
	level=$2
	shift
	shift
	id=$3

	write_debug "Level $level, function $funct running with id $id"
	
}

function test_excluded()
{
	local excl num
	excl=$1
	num=0
	ex_test=($(echo "$excl" | sed 's/,/ /g'))

	while [ -n "${ex_test[num]}" ]; do
		if [ "$(echo "${ex_test[num]}" | awk -F . '{if($1 == 1) print 0}')" == "0" ]; then
			var=$(echo "${ex_test[num]}" | sed 's/^[[:digit:]]\.//g')
			excl_arr1+=("${var}")
		elif [ "$(echo "${ex_test[num]}" | awk -F . '{if($1 == 2) print 0}')" == "0" ]; then
			var=$(echo "${ex_test[num]}" | sed 's/^[[:digit:]]\.//g')
                        excl_arr2+=("${var}")
		else
			echo "Invalid format or value being passed"
		fi

		num=$((num + 1))
	done
}
		###  Display result in table format  ###
function retrieve()
{
	local description formatter pass fail na level all
	pass=0
	fail=0
	na=0
	description=""
	formatter=""
	level=$1
	all=$2

	#create textfile
	touch "$JSN_DIR/retrieve.txt"

	l1Array=("one" "two" "three" "four" "five" "six")
	l2Array=("one" "three" "four" "five" "six")

	if [[ $level -eq 1 ]] || [[ $all -eq 1 ]]; then
		echo "LEVEL 1"
		for chp in "${l1Array[@]}"; do
			echo "========="
			echo "Chp $chp"
			echo "========="
			catidArr1=($(jq -c --arg chp ${chp} ".audit[] | select(.level==1) | .chapters[\"$chp\"].categories[] | .id" "$JSN_DIR/$JSN_FIL")) 
			for cid in "${catidArr1[@]}"; do
				pass=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==1) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .report[]" "$JSN_DIR/$JSN_FIL" | grep "Pass" | wc -l)
				fail=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==1) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .report[]" "$JSN_DIR/$JSN_FIL" | grep "Fail" | wc -l)
				na=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==1) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .report[]" "$JSN_DIR/$JSN_FIL" | grep "Null" | wc -l)
				description=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==1) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .name" "$JSN_DIR/$JSN_FIL")
				description=$(echo "${description}" | sed -e "s/\"//g")
				echo "$cid,$description,$pass,$fail,$na,$total" >> "$JSN_DIR/retrieve.txt"
			done
			( 
				echo -e "\t--,-----------,----,----,----" 
				echo -e "\tID,Description,Pass,Fail,Null"
				echo -e "\t--,-----------,----,----,----"
				while read line; do
					echo -e "\t$line" 
				done < "$JSN_DIR/retrieve.txt"
			) | column -t -s ","
		done
	fi

	echo " "
	echo " "

	if [[ $level -eq 2 ]] || [[ $all -eq 1 ]]; then
		echo "LEVEL 2"
                for chp in "${l2Array[@]}"; do
                        echo "========="
                        echo "Chp $chp"
                        echo "========="
                        catidArr2=($(jq -c --arg chp ${chp} ".audit[] | select(.level==2) | .chapters[\"$chp\"].categories[] | .id" "$JSN_DIR/$JSN_FIL"))
                        for cid in "${catidArr2[@]}"; do
                                pass=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==2) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .report[]" "$JSN_DIR/$JSN_FIL" | grep "Pass" | wc -l)
                                fail=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==2) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .report[]" "$JSN_DIR/$JSN_FIL" | grep "Fail" | wc -l)
                                na=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==2) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .report[]" "$JSN_DIR/$JSN_FIL" | grep "Null" | wc -l)
                                description=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==2) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .name" "$JSN_DIR/$JSN_FIL")
				description=$(echo "${description}" | sed -e "s/\"//g")
				echo "$cid,$description,$pass,$fail,$na,$total" >> "$JSN_DIR/retrieve.txt"
                        done
                        (
                                echo -e "\t--,-----------,----,----,----"  
                                echo -e "\tID,Description,Pass,Fail,Null" 
                                echo -e "\t--,-----------,----,----,----" 
				while read line; do
					echo -e "\t$line"
				done < "$JSN_DIR/retrieve.txt"  
                        ) | column -t -s "," 
                done
        fi


	rm "$JSN_DIR/retrieve.txt" 
}


		###   COMMON FUNCTION FOR BOTH LVL 1 & 2, ACROSS ALL CHAPTERS	###
function not_scored()
{
	local id 
	level=$1
	chp=$2
	catid=$3
	id=$4

	result="Null"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function chkpkg_installed()
{
	#verify if the package is installed/not installed
	local id pkge isinstall
	level=$1
	chp=$2
	catid=$3
	id=$4
	pkge=$5
	isinstall=$6

	#description: Ensure pkge is installed/not installed

	#= TEST =#
	if [[ "$isinstall" -eq 1 ]]
	then
		[ $(rpm -qa $pkge &> /dev/null; echo $?) -eq 0 ] && result="Pass"
	elif [[ "$isinstall" -eq 0 ]]
	then
		[ $(rpm -qa $pkge &> /dev/null; echo $?) -eq 1 ] && result="Pass"
	fi

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function is_enabled()
{
	local id service
	level=$1
	chp=$2
	catid=$3
	id=$4
	service=$5

	#= TEST =#
	[ $(systemctl is-enabled $service | grep enabled | wc -l) -ne 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function is_disabled()
{
	## Local Variables ##
	local id score var
	level=$1
	chp=$2
	catid=$3
	id=$4
	var=$5
	score=0

	#description="Ensure $var is disabled

	#= TEST =#
	[[ "$(modprobe -n -v $var 2> /dev/null | tail -1)" =~ "install /bin/true" ]] && score=$((score+1))
	[ $(lsmod | grep $var | wc -l) -eq 0 ] && score=$((score+1))
	[ $score -eq 2 ] && result="Pass"

	#Append the result to LOG_FILE
	write_result "$level" "$chp" "$catid" "$id" "$result"

}



		###---------- LEVEL 1 ----------###
		## -- CHAPTER ONE --##
## -- FILESYSTEM FUNCTION -- ##
#Ensure /tmp is configured
function tmp_config()
{
	## Local Variables ##
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4
	score=0

	#description="Ensure /tmp is configured"

	#= TEST =#
	[[ "$(mount | grep -E '\s/tmp\s')" =~ ".*tmpfs\s\(rw.*nosuid.*nodev.*noexec.*relatime\)" ]] && score=$((score+1))
	[ $(systemctl is-enabled tmp.mount 2> /dev/null | grep -E 'disabled' |wc -l) -ne 0 ] && score=$((score+1))
	[ $score -eq 2 ] && result="Pass"

	#Append the result to LOG_FILE
	write_result "$level" "$chp" "$catid" "$id" "$result"

}

#Check for nosuid, nodev, noexec
function check_fs_option()
{
	## Local Variables ##
	local id partition isScored score
	level=$1
	chp=$2
	catid=$3
	id=$4
	partition=$5
	isScored=$6
	score=0

	#description="Ensure nodev, nosuid, noexec option set on $partition partition"

	#= TEST =#
	#check for nodev
	[ $(mount | grep -E "\s$partition\s" | grep -v nodev | wc -l) -eq 0 ] && score=$((score+1))
	#check for nosuid
	[ $(mount | grep -E "\s$partition\s" | grep -v nosuid | wc -l) -eq 0 ] && score=$((score+1))
	#check for noexec
	[ $(mount | grep -E "\s$partition\s" | grep -v noexec | wc -l) -eq 0 ] && score=$((score+1))

	[ $score -eq 3 ] && result="Pass"


	#Append the result to LOG_FILE
	write_result "$level" "$chp" "$catid" "$id" "$result"

}

#Ensure Sticky bit is set on all world-writable directories
function sticky_bit()
{
	local id
	level=$1
	chp=$2
	catid=$3
	id=$4

	#description="Ensure sticky bit is set on all world-writable directories"

	#= TEST =#
	[ $(df --local -P | awk '{if (NR!=1) print$6}'| xargs -l '{}' find '{}' -xdev -type d \( -perm -002 -a ! -perm -1000 \) 2> /dev/null | wc -l) -eq 0 ] && result="Pass"
	
	#Append result to LOG_FILE
	write_result "$level" "$chp" "$catid" "$id" "$result" 
}

#Disable Automounting
function disable_automount()
{
	local id
	level=$1
	chp=$2
	catid=$3
	id=$4

	#description="Disable Automounting"

	#= TEST =#
	[ $(systemctl is-enabled autofs 2> /dev/null | grep -E 'disabled' | wc -l) -ne 0 ] && result="Null"
	
	#Append result to LOG_FILE
	write_result "$level" "$chp" "$catid" "$id" "$result"

}


##-- SOFTWARE UPDATE --##
function gpg_check()
{
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4
	score=0

	#description: Ensure gpgcheck is globally activated 

	#= TEST =#
	[ $(grep ^gpgcheck=1 /etc/yum.conf | wc -l) -ne 0 ] && score=$((score+1))
	[ $(grep ^gpgcheck=1 /etc/yum.repos.d/* | wc -l) -eq $(grep ^gpgcheck /etc/yum.repos.d/* | wc -l) ] && score=$((score+1))
	[ $score -eq 2 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

##-- SUDO --##
function check_pty()
{
	local id
	level=$1
	chp=$2
	catid=$3
	id=$4

	#description: Ensure sudo commands use pty

	#= TEST =#
	[ $(grep -Ei '^\s*Defaults\s+(\[^#]+,\s*)?use_pty' /etc/sudoers /etc/sudoers.d/* 2> /dev/null | wc -l) -ne 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function sudo_log()
{
	local id 
	level=$1
	chp=$2
	catid=$3
	id=$4

	#description: Ensure sudo log file exists

	#= TEST =#
	[ $(grep -Ei '^\s*Defaults\s+(\[^#]+,\s*)?use_pty' /etc/sudoers /etc/sudoers.d/* 2> /dev/null | wc -l) -ne 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}


##-- FILESYSTEM INTEGRITY CHECKING --##
function fs_periodic_check()
{
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4
	score=0

	#description: Ensure filesystem integrity is regularly checked 

	#= TEST =#
	[[ "$(systemctl is-enabled aidecheck.service 2> /dev/null)" =~ "enabled" ]] && score=$((score+1))
	[[ "$(systemctl status aidecheck.service 2> /dev/null)" =~ "active" ]] && score=$((score+1))
	[ $score -eq 2 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"
}


##-- Secure Boot Settings --##
function boot_config()
{
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4
	score=0

	#description: Ensure permissions on bootloader config are configured

	#= TEST =#
	[ $(stat /boot/grub2/grub.cfg /boot/grub2/grubenv | grep 0600 | wc -l) -eq 2 ] && score=$((score+1))
	[ $(stat /boot/grub2/grub.cfg /boot/grub2/grubenv | egrep -o "0\/\s+root" | wc -l) -eq 4 ] && score=$((score+1))
       	[ $score -eq 2 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function boot_passwd()
{
	local id 
	level=$1
	chp=$2
	catid=$3
	id=$4

	#description: Ensure bootloader password is set

	#= TEST =#
	[ $(grep "^\s*GRUB2_PASSWORD" /boot/grub2/user.cfg 2> /dev/null | wc -l) -ne 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function auth_single_usr()
{
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4

	#description: Ensure authentication required for single user mode

	#= TEST =#
	[ $(grep /systemd-sulogin-shell /usr/lib/systemd/system/rescue.service /usr/lib/systemd/system/emergency.service 2> /dev/null | wc -l) -eq 2 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"	

}


##-- Additional Process Hardening --##
function cd_restrict()
{
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4
	score=0
	
	#description: Ensure core dumps are restricted

	#= TEST =#
	[ $(grep -E "^\s*\*\s+hard\s+core" /etc/security/limits.conf /etc/security/limits.d/* 2> /dev/null | wc -l) -ne 0 ] && score=$((score+1))
	[ $(sysctl fs.suid_dumpable | wc -l) -ne 0 ] && score=$((score+1))
	[ $(grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | wc -l) -ne 0 ] && score=$((score+1))
	[ $(systemctl is-enabled coredump.service 2> /dev/null | wc -l) -ne 0 ] && score=$((score+1))
	[ $score -eq 4 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function alsr_enabled()
{
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4
	score=0

	#description; Ensure address space layout randomization (ALSR) is enabled

	#= TEST =#
	[ $(sysctl kernel.randomize_va_space | grep 2 | wc -l) -ne 0 ] && score=$((score+1))
	[ $(grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | wc -l ) -ne 0 ] && score=$((score+1))
	[ $score -eq 2 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}


##-- Message of the Day --##
function motd_config()
{
	local id motd score
	level=$1
	chp=$2
	catid=$3
	id=$4
	motd=$5
	score=0

	#description: Ensure messages|local login warning banner|remote login warning banner & permissions are configured properly
	#files: /etc/motd , /etc/issue , /etc/issue.net

	#= TEST =#
	[ $(cat "$motd" | wc -l) -ne 0 ] && score=$((score+1))
	[[ $(grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" "$motd" | wc -l) -eq 0 ]] && score=$((score+1))
	[ $(stat $motd | grep 0644 | wc -l) -ne 0 ] && score=$((score+1))
	[ $(stat $motd | egrep -o "0\/\s+root" | wc -l) -eq 2 ] && score=$((score+1))
	[ $score -eq 4 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function gdm_config()
{
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4
	score=0

	#description: Ensure GDM login banner is configured

	#= TEST =#
	gdm_file="/etc/dconf/profile/gdm"
	banner_file="/etc/dconf/db/gdm.d/01-banner-message"

	if [[ "$(rpm -q gdm)" != "package gdm is not installed" ]]
	then
		if [ -f $gdm_file ]
		then
			if [ -f $banner_file ]
			then
				[ $(egrep "^banner-message-enable=true" $banner_file | wc -l) -eq 1 ] && score=$((score+1))
				[ $(egrep "banner-message-text=.*" $banner_file | wc -l) -eq 1 ] && score=$((score+1))
				[ $score -eq 2 ] && result="Pass"
			fi
		fi
	fi

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function crypto_policy()
{
        local id legacy
        level=$1
        chp=$2
        catid=$3
        id=$4
	legacy=$5

        #description: Ensure system-wide crypto policy is not legacy
	#description: Ensure system-wide crypto policy is FUTURE or FIPS

        #= TEST =#
	if [ $legacy -eq 1 ]
	then
        	[ $(grep -E -i '^\s*LEGACY\s*(\s+#.*)?$' /etc/crypto-policies/config | wc -l) -eq 0 ] && result="Pass"
	else
		[ $(grep -E -i '^\s*(FUTURE|FIPS)\s*(\s+#.*)?$' /etc/crypto-policies/config | wc -l) -ne 0 ] && result="Pass"
	fi

        write_result "$level" "$chp" "$catid" "$id" "$result"

}

		## -- CHAPTER TWO -- ##
function chrony_config()
{
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4
	score=0
	
	#description: Ensure chrony is configured

	#= TEST =#
	[ $(grep -E "^(server|pool)" /etc/chrony.conf &> /dev/null; echo $?) -eq 0 ] && score=$((score+1))
	[ $(ps -ef | grep chronyd &> /dev/null; echo $?) -eq 0 ] && score=$((score+1))
	[ $score -eq 2 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"
}

function not_enabled()
{
	local id 
	level=$1
        chp=$2
        catid=$3
        id=$4
	serv=$5

	#description: Ensure these services are not enabled

	#= TEST =#
	[ $(systemctl is-enabled $serv 2> /dev/null | grep disabled | wc -l) -ne 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function mail_tagent()
{
	local id 
        level=$1
        chp=$2
        catid=$3
        id=$4
	
	#description: Ensure mail transfer agent is configured

	#= TEST =#
	[ $(ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s' &> /dev/null; echo $?) -eq 0 ] && result="Pass"

	 write_result "$level" "$chp" "$catid" "$id" "$result"

}

		## -- CHAPTER THREE -- ##
##--Network Parameter (Host Only) && (Host and Router)--##
function sysctl_1()
{
	local id protocol query ipv6 query6 score
	level=$1
	chp=$2
	catid=$3
	id=$4
	query=$5
	ipv6=$6
	query6=$7
	score=0

	#= TEST =#
	if [ $ipv6 != 0 ] #Check if ipv6 is needed for the Test
	then
		[ $(sysctl net.ipv4.$query | grep 0 | wc -l) -ne 0 ] && score=$((score+1))
		[ $(grep -E -s "^\s*net\.ipv4\.$query\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | wc -l) -eq 0 ] && score=$((score+1))

		[ $(sysctl net.ipv6.conf.all.$query6 | grep 0 | wc -l) -ne 0 ] && score=$((score+1))
		[ $(grep -E -s "^\s*net\.ipv6\.conf\.all\.$query6\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | wc -l) -eq 0 ] && score=$((score+1))

		[ $score -eq 4 ] && result="Pass"
	else
		[ $(sysctl net.ipv4.$query | grep 0 | wc -l) -ne 0 ] && score=$((score+1))
                [ $(grep -E -s "^\s*net\.ipv4\.$query\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | wc -l) -eq 0 ] && score=$((score+1))

		[ $score -eq 2 ] && result="Pass"
	fi

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function sysctl_2()
{
	local id protocol query ipv6 score
	level=$1
	chp=$2
	catid=$3
	id=$4
	query=$5
	ipv6=$6
	score=0

	#= Test =#
	if [ $ipv6 != 0 ]
	then
		#IPv4
		[ $(sysctl net.ipv4.conf.all.$query 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))
		[ $(grep "net\.ipv4\.conf\.all\.$query" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))
		[ $(sysctl net.ipv4.conf.default.$query 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))
		[ $(grep "net\.ipv4\.conf\.default\.$query" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))

		#IPv6
		[ $(sysctl net.ipv6.conf.all.$query 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))
                [ $(grep "net\.ipv6\.conf\.all\.$query" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))
                [ $(sysctl net.ipv6.conf.default.$query 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))
                [ $(grep "net\.ipv6\.conf\.default\.$query" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))


	else
		[ $(sysctl net.ipv4.conf.all.$query 2> /dev/null | grep 0 | wc -l) -ne 0 ] && score=$((score+1))
                [ $(grep "net\.ipv4\.conf\.all\.$query" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))
                [ $(sysctl net.ipv4.conf.default.$query 2> /dev/null| grep 0 | wc -l) -ne 0 ] && score=$((score+1))
                [ $(grep "net\.ipv4\.conf\.default\.$query" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))

	fi

	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function ipv6_route()
{
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4
	score=0

	#= TEST =#
	[ $(sysctl net.ipv6.conf.all.accept_ra 2> /dev/null | grep 0 | wc -l) -ne 0 ] && score=$((score+1))
        [ $(grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/* | grep 0 | wc -l) -ne 0 ] && score=$((score+1))
	[ $(sysctl net.ipv6.conf.default.accept_ra 2> /dev/null | grep 0 | wc -l) -ne 0 ] && score=$((score+1))
	[ $(grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/* | grep 0 | wc -l) -ne 0 ] && score=$((score+1))

	[ $score -eq 4 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

##--Firewall Configuration--##
function fw_isinstall()
{
	local id
	level=$1
	chp=$2
	catid=$3
	id=$4

	#description: Ensure firewalld, nftables & iptables are installed

	#= TEST =#
	[ $(rpm -q firewalld &> /dev/null;echo $?) -eq 0 ] && [ $(rpm -q nftables &> /dev/null;echo $?) -eq 0 ] && [ $(rpm -q iptables &> /dev/null;echo $?) -eq 0 ] && result="Pass" 

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fw_chkenabled()
{
	local id serv
	level=$1
	chp=$2
	catid=$3
	id=$4
	serv=$5

	#description: Check if firewalld is enabled & running; Check if nftables & iptables are disabled and inactive	

	#= TEST =#
	if [ "$serv" == "firewalld" ]
	then
		[ $(systemctl is-enabled firewalld | grep enabled | wc -l) -ne 0 ] && [ $(firewall-cmd --state | grep running | wc -l) -ne 0 ] && result="Pass"
	else
		[ $(systemctl is-enabled $serv 2> /dev/null | grep disabled | wc -l) -ne 0 ] && [ $(systemctl status $serv 2>/dev/null | grep dead | wc -l) -ne 0 ] && result="Pass"

	fi
	

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function default_zone()
{
	local id
	level=$1
	chp=$2
	catid=$3
	id=$4
	
	#description: Ensure default zone is set

	#= TEST =#
	[ $(firewall-cmd --get-default-zone &> /dev/null;echo $?) -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function nft_1()
{
	local id var
	level=$1
	chp=$2
	catid=$3
	id=$4
	var=$5

	#= TEST =#
	[ $(nft list $var | wc -l) -ne 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function nft_2()
{
	local id score policy
	level=$1
	chp=$2
	catid=$3
	id=$4
	policy=$5
	score=0

	#= TEST =#
	if [[ "$policy" == "drop" ]]
	then
		[ $(nft list ruleset | grep 'hook input' | grep drop | wc -l) -ne 0 ] && score=$((score+1))
        	[ $(nft list ruleset | grep 'hook forward' | grep drop | wc -l) -ne 0 ] && score=$((score+1))
        	[ $(nft list ruleset | grep 'hook output' | grep drop | wc -l) -ne 0 ] && score=$((score+1))
	else
		[ $(nft list ruleset | grep 'hook input' | wc -l) -ne 0 ] && score=$((score+1))
		[ $(nft list ruleset | grep 'hook forward' | wc -l) -ne 0 ] && score=$((score+1))
		[ $(nft list ruleset | grep 'hook output' | wc -l) -ne 0 ] && score=$((score+1))
	fi

	[ $score -eq 3 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function nft_3()
{
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4
	score=0

	#= TEST =#
	[ $(nft list ruleset | awk '/hook input/,/}/' | grep 'iif "lo" accept' &> /dev/null; echo $?) -ne 1 ] && score=$((score+1))
	[ $(nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr' &> /dev/null; echo $?) -ne 1 ] && score=$((score+1))
	[ $(nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr' &> /dev/null; echo $?) -ne 1 ] && score=$((score+1))

	[ $score -eq 3 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function chk_iptables()
{
	local id score var protocol
	level=$1
        chp=$2
        catid=$3
        id=$4
	var=$5
	score=0

	if [ "$var" == "loopback" ]
	then
		[ $(iptables -L INPUT -v -n | grep lo | wc -l) -ne 0 ] && [ $(iptables -L INPUT -v -n | grep 127 | wc -l) -ne 0 ] || score=$((score+1))
		[ $(iptables -L OUTPUT -v -n | grep lo | wc -l) -ne 0 ] || score=$((score+1))
	else
		[ $(iptables -L | grep -E 'INPUT (policy DROP)') ] || score=$((score+1))
		[ $(iptables -L | grep -E 'FORWARD (policy DROP)') ] || score=$((score+1))
		[ $(iptables -L | grep -E 'OUTPUT (policy DROP)') ] || score=$((score+1))
	fi

	[ $score -eq 0 ] && result="Pass"

	 write_result "$level" "$chp" "$catid" "$id" "$result"

}

function nftrul_perm()
{
	local id score
	level=$1
        chp=$2
        catid=$3
        id=$4
	score=0

	#= TEST =#
	#INPUT
	[ $([[ -n $(grep -E "^\s*include" /etc/sysconfig/nftables.conf) ]] && awk '/hook input/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/sysconfig/nftables.conf); echo $?) -ne 1 ] && score=$((score+1))

	#FORWARD
	[ $([[ -n $(grep -E "^\s*include" /etc/sysconfig/nftables.conf) ]] && awk '/hook forward/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/sysconfig/nftables.conf);echo $?) -ne 1 ] && score=$((score+1))

	#OUTPUT
	[ $([[ -n $(grep -E "^\s*include" /etc/sysconfig/nftables.conf) ]] && awk '/hook output/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/sysconfig/nftables.conf);echo $?) -ne 1 ] && score=$((score+1))

	[ $score -eq 3 ] && result="Pass"

	 write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fwll_op()
{
	local id score var arr
	level=$1
        chp=$2
        catid=$3
        id=$4
	score=0

	#description: Ensure firewall rules exist for all open ports

	#= TEST =#
	var=$(ss -4tuln | awk  '{print $5}' | awk -F ':' '{print $2}' | awk NR\>1)
	arr=($var)
	total=${#arr[@]}

	for i in "${var[@]}"
	do
		[ $(iptables -L INPUT -v -n | grep ":$i" | grep ACCEPT &> /dev/null; echo $?) -ne 1 ] && score=$((score+1))
	done

	[ $score -eq $total ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function chk_ip6tables()
{
	local id score var
	level=$1
        chp=$2
        catid=$3
        id=$4
	var=$5

	#description: Ensure IPv6 loopback traffic is configured

	#= TEST =#
	if [ "$var" == "loopback" ]
	then
		[ $(ip6tables -L INPUT -v -n | grep lo | grep ACCEPT | wc -l) -ne 0 ] || score=$((score+1))
		[ $(ip6tables -L INPUT -v -n | grep ::1 | grep DROP | wc -l) -ne 0 ] || score=$((score+1))
		[ $(ip6tables -L OUTPUT -v -n | grep lo | grep ACCEPT | wc -l) -ne 0 ] || score=$((score+1))
	else
		[ $(ip6tables -L | grep -E 'INPUT (policy DROP)') ] || score=$((score+1))
                [ $(ip6tables -L | grep -E 'FORWARD (policy DROP)') ] || score=$((score+1))
                [ $(ip6tables -L | grep -E 'OUTPUT (policy DROP)') ] || score=$((score+1))
	fi

	[[ $score -eq 0 ]] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function wifi_config()
{
	local id
	level=$1
        chp=$2
        catid=$3
        id=$4

	[ $(nmcli radio all | awk '{print $2}' | grep disabled | wc -l) -ne 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}


		## -- CHAPTER FOUR -- ##
##-- CONFIGURE LOGGING --##
function rsyslog_perm()
{
	local id
	level=$1
        chp=$2
        catid=$3
        id=$4
	
	#description: Ensure rsyslog default file permissions configured

	#= TEST =#
	[ $(grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2> /dev/null | grep -E '(0640||0600)' | wc -l) -ne 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function send_log()
{
	local id
	level=$1
        chp=$2
        catid=$3
        id=$4

	#description: Ensure rsyslog is configured to send logs to a remote log host (Scored)

	#= TEST =#
	[ $(grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2> /dev/null | wc -l) -ne 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"
}

function journald_cfg()
{
	local id query
	level=$1
        chp=$2
        catid=$3
        id=$4

	#function created for id 4.1.6/.7/.8

	#= TEST =#
	if [[ "$id" =~ ".6" ]]
	then
		[ $(grep -e ^\s*ForwardToSyslog /etc/systemd/journald.conf 2> /dev/null | wc -l) -ne 0 ] && result="Pass"
	elif [[ "$id" =~ ".7" ]]
	then
		[ $(grep -e ^\s*Compress /etc/systemd/journald.conf 2> /dev/null | wc -l) -ne 0 ] && result="Pass"
	elif [[ "$id" =~ ".8" ]]
	then
		[ $(grep -e ^\s*Storage /etc/systemd/journald.conf 2> /dev/null | wc -l) -ne 0 ] && result="Pass"
	fi

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function permlog_cfg()
{
	local id
	level=$1
        chp=$2
        catid=$3
        id=$4

	#description: Ensure permissions on all logfiles are configured

	#= TEST =#
	[ $(find /var/log -type f -perm /037 -ls -o -type d -perm /026 -ls 2> /dev/null | wc -l) -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}


		## -- CHAPTER FIVE -- ##
##-- CONFIGURE CRON --##
function cron_perm1()
{
	local id score query
	level=$1
        chp=$2
        catid=$3
        id=$4
	query=$5
	score=0

	#= TEST =#
	[ $(stat /etc/cron${query} 2> /dev/null | egrep "^Access:\s+\S+(0600|0700)\/\S+" | wc -l) -ne 0 ] && score=$((score+1))
	[ $(stat /etc/cron${query} 2> /dev/null | egrep -o "0\/\s+root" | wc -l) -eq 2 ] && score=$((score+1))

	[ $score -eq 2 ] && result="Pass"

	 write_result "$level" "$chp" "$catid" "$id" "$result"

}

function cron_perm2()
{
	local id score
	level=$1
        chp=$2
        catid=$3
        id=$4
	score=0

	#= TEST =#
	[ $(stat /etc/cron.deny &> /dev/null; echo $?) -eq 1 ] || score=$((score+1))
	[ $(stat /etc/at.deny &> /dev/null; echo $?) -eq 1 ] || score=$((score+1))

	[ $(stat /etc/cron.allow 2> /dev/null | egrep "^Access:\s+\S+(0600|0700)\/\S+" | wc -l) -ne 0 ] || score=$((score+1))
	[ $(stat /etc/cron.allow 2> /dev/null | egrep -o "0\/\s+root" | wc -l) -ne 0 ] || score=$((score+1))

	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}


##-- SSH SERVER CONFIGURATION --##
function ssh_perm()
{
	local id score
	level=$1
        chp=$2
        catid=$3
        id=$4

	#= TEST =#
	[ $(stat /etc/ssh/sshd_config | egrep "^Access:\s+\S+(0600|0700)\/\S+" | wc -l) -ne 0 ] && score=$((score+1))
	[ $(stat /etc/ssh/sshd_config | egrep -o "0\/\s+root" | wc -l) -eq 2 ] && score=$((score+1))

	[ $score -eq 2 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function ssh_key_config()
{
	local id score pub total
	level=$1
        chp=$2
        catid=$3
        id=$4
	pub=$5
	score=0

	#= TEST =#
	if [[ "$pub" -ne 1 ]]
	then
		total=$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | egrep -o "File:\s+\S+" | wc -l)
		[ $(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | egrep "^Access:\s+\S+(0600|0700)\/\S+" | wc -l) -ne 0 ] || score=$((score+1))
		[ $(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | egrep "0\/\s+root" | wc -l) -eq ${total} ] || score=$((score+1))

	else
		total=$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \; | egrep -o "File:\s+\S+" | wc -l)
                [ $(find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \; | egrep "^Access:\s+\S+(0600|0700)\/\S+" | wc -l) -ne 0 ] || score=$((score+1))
                [ $(find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \; | egrep "0\/\s+root" | wc -l) -eq ${total} ] || score=$((score+1))
	fi

	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function ssh_cfg_1()
{
	local id var query double
	level=$1
        chp=$2
        catid=$3
        id=$4
	var=$5
	query=$6
	

	#= TEST =#
	[ $(sshd -T | grep ${var} | egrep "${query}" | wc -l) -ne 0 ] && result="Pass"


	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function ssh_cfg_2()
{
	local id score var1 var2 query1 query2
	level=$1
        chp=$2
        catid=$3
        id=$4
	var1=$5
	var2=$6
	query1=$7 
	query2=$8
	score=0

	#= TEST =#
	[ $(sshd -T | grep ${var1} | egrep "${query1}" | wc -l) -ne 0 ] || score=$((score+1))
	[ $(sshd -T | grep ${var2} | egrep "${query2}" | wc -l) -ne 0 ] || score=$((score+1))

	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function ssh_cfg_3()
{
	local id
	level=$1
        chp=$2
        catid=$3
        id=$4

	#= TEST =#
	[ $(sshd -T | grep -E "^\s*(allow|deny)(users|groups)\s+\S+()" | wc -l) -eq 4 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function ssh_crypto()
{
	local id 
	level=$1
        chp=$2
        catid=$3
        id=$4

	#= TEST =#
	[ $(grep '^/s*CRYPTO_POLICY=' /etc/sysconfig/sshd | wc -l) -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

## -- CONFIGURE AUTHSELECT -- ##
function auth_custom()
{
	local id score
	level=$1
        chp=$2
        catid=$3
        id=$4
	score=0

	#= TEST =#
	[ $(authselect current | grep "Profile ID:" | wc -l) -ne 0 ] || score=$((score+1))
	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}
	
function auth_profile()
{
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4
	score=0

	#= TEST =#
	[ $(authselect current | egrep "sudo|faillock|nullok" | wc -l) -eq 3 ] || score=$((score+1))
	[ $score -eq 0 ] && resul="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function auth_flck()
{
	local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        score=0	

	#= TEST =#
	[ $(authselect current | grep with-faillock | wc -l) -ne 0 ] || score=$((score+1))
	[ $(grep with-faillock /etc/authselect/authselect.conf | wc -l) -ne 0 ] || score=$((score+1))

	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

##-- CONFIGURE PAM --##
function pam_config()
{
	local id score
	level=$1
        chp=$2
        catid=$3
        id=$4
        score=0
	
	#= TEST =#
	if [[ "$id" == "5.4.0" ]]
	then
		[ $(egrep -c "pam_pwquality.so.*try_first_pass.*local_users_only.*enforce-for-root.*retry=3" /etc/pam.d/system-auth ) -eq 1 ] || score=$((score+1))
		[ $(egrep -c "pam_pwquality.so.*try_first_pass.*local_users_only.*enforce-for-root.*retry=3" /etc/pam.d/password-auth) -eq 1 ] || score=$((score+1))
		minlen=$(grep ^minlen /etc/security/pwquality.conf | cut -f4 -d' ')
		[[ $minlen -ge 14 ]] || score=$((score+1))
	
	elif [[ "$id" == "5.4.1" ]]
	then
		[ $(egrep -c "^auth\s+required\s+pam_faillock.so.*preauth.*silent.*deny=5.*unlock_time=900" /etc/pam.d/system-auth) -eq 1 ] || score=$((score+1))
		[ $(egrep -c "^auth\s+required\s+pam_faillock.so.*authfail.*silent.*deny=5.*unlock_time=900" /etc/pam.d/system-auth) -eq 1 ] || score=$((score+1))

		[ $(egrep -c "^auth\s+required\s+pam_faillock.so.*preauth.*silent.*deny=5.*unlock_time=900" /etc/pam.d/password-auth) -eq 1 ] || score=$((score+1))
		[ $(egrep -c "^auth\s+required\s+pam_faillock.so.*authfail.*silent.*deny=5.*unlock_time=900" /etc/pam.d/password-auth) -eq 1 ] || score=$((score+1))

	elif [[ "$id" == "5.4.2" ]]
	then
		[ $(egrep -c "^\s*password\s+(requisite|sufficient)\s+(pam_pwquality\.so|pam_unix\.so)\s+.*remember=([5-9]|[1-4][0-9])[0-9]*\s*.*$" /etc/pam.d/system-auth) -eq 1 ] || score=$((score+1))

	elif [[ "$id" == "5.4.3" ]]
	then
		[ $(egrep -c "^\s*password\s+sufficient\s+pam_unix.so\s+.*sha512\s*.*$" /etc/pam.d/system-auth) -eq 1 ] || score=$((score+1))
		[ $(egrep -c "^\s*password\s+sufficient\s+pam_unix.so\s+.*sha512\s*.*$" /etc/pam.d/password-auth) -eq 1 ] || score=$((score+1))

	fi

	[ $score -eq 0 ] && result="Pass"

	 write_result "$level" "$chp" "$catid" "$id" "$result"

}

##-- User Accounts and Environment (UAE) --##
function uae_cfg ()
{
	local id var val cut 
	level=$1
        chp=$2
        catid=$3
        id=$4
	var=$5
	val=$6
	cut=$7

	#= CHECKING FOR PASSWD_REVIEW_LIST =#
	if [[ -d "${LOG_DIR}/pwd_review_list" ]]
	then
		if [[ -f usr_list ]]
		then
			write_info "usr_list exist under ${LOG_DIR}/pwd_review_list"
		else
			touch "${LOG_DIR}/pwd_review_list/usr_list"
		fi
	else
		mkdir "${LOG_DIR}/pwd_review_list"
		touch "${LOG_DIR}/pwd_review_list/usr_list"
		write_info "Directory ${LOG_DIR}/pwd_review_list created"
		write_info "${LOG_DIR}/pwd_review_list/usr_list file created"
	fi

	#= TEST =#
	if [[ "$id" == "5.5.3" ]]
	then
		[[ $(useradd -D | grep "^${var}" | cut -f2 -d = ) -eq $val ]] && result="Pass"

	else
		[[ $(grep "^${var}" /etc/login.defs | cut -f2 ) -eq $val ]] && result="Pass"
	fi

	#= REVIEW LIST OF USERS that does not conforms the policy =#
	echo "$(date -Ins)"
	echo "Users whose account ${var}'s value is less than ${val}...." >> "${LOG_DIR}/pwd_review_list/usr_list"
	awk -F ":" -e '/^[^:]+:[^\!*]/ && $4 != '${val}' {print $1,$4}' /etc/shadow >> "${LOG_DIR}/pwd_review_list/usr_list"
	echo "=======================================================================================" >>  "${LOG_DIR}/pwd_review_list/usr_list"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function pwd_cfg()
{
	local id score 
	level=$1
        chp=$2
        catid=$3
        id=$4
	score=0

	#= TEST =#
	for user in $(cut -d: -f1 /etc/shadow); do 
		last_date=$(chage --list $user | grep "^Last password change" | cut -d: -f2)

		if [[ "$last_date" != " never" ]]; then
			[[ "$(date -d "$chge_date" +%s)" -lt "$(date +%s)" ]] || score=$((score+1))
		fi
	done

	[ $score -eq 0 ] && result="Pass" 


	write_result "$level" "$chp" "$catid" "$id" "$result"

}


function sysacc_secured()
{
	local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
	score=0

	#= TEST =#
	[ $(awk -F: '($1 != "root" && $1 != "sync" && $1!="shutdown" && $1 != "halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="/sbin/nologin" && $7!="/bin/false") {print}' /etc/passwd | wc -l) -eq 0 ] && score=$((score+1))
	[ $(awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}' | wc -l) -eq 0 ] && score=$((score+1))

	[ $score -eq 2 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function def_usr_shell()
{
	local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        score=0

	#= TEST =#
	[ $(grep "^TMOUT" /etc/bashrc | grep 900 | wc -l) -ne 0 ] && score=$((score+1))
	[ $(grep "^TMOUT" /etc/profile /etc/profile.d/*.sh | grep 900 | wc -l) -ne 0 ] &&score=$((score+1))

	[ $score -eq 2 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function def_grp_access()
{
	local id 
	level=$1
        chp=$2
        catid=$3
        id=$4

	#= TEST =#
	[ $(grep "^root:" /etc/passwd | cut -f4 -d:) -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function def_usr_umask()
{
	local id score umask
	level=$1
        chp=$2
        catid=$3
        id=$4
	score=0

	#= TEST =#
	umask=$(egrep -c "\s+umask\s+[0-9]" /etc/bashrc)
	[ $(grep "umask" /etc/bashrc | egrep -c "0[0-2][0-7]") -eq ${umask} ] && score=$((score+1))
	[ $(grep "umask" /etc/profile /etc/profile.d/*.sh | egrep -c "0[0-7][3-7]") -eq ${umask} ] && score=$((score+1))

	[ $score -eq 2 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

##-- Su Command --##
function su_access()
{
	local id 
        level=$1
        chp=$2
        catid=$3
        id=$4

	#= TEST =#
	[ $(egrep -c "^auth\s+required\s+pam_wheel.so\s+use_uid" /etc/pam.d/su) -eq 1 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}


		## -- CHAPTER SIX -- ##
## -- SYSTEM FILE PERMISSIONS -- ##
function file_perm()
{
	local id score file perm
	level=$1
        chp=$2
        catid=$3
        id=$4
	file=$5
	${perm}
	score=0

	#= TEST =#
	[ $(stat ${file} | egrep "^Access:\s+\(${perm}\/\S+" | wc -l) -ne 0 ] && score=$((score+1))
	[ $(stat ${file} | egrep -o "0\/\s+root" | wc -l) -eq 2 ] && score=$((score+1))

	[ $score -eq 2 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}


function no_exist()
{
	local id 
	level=$1
        chp=$2
        catid=$3
        id=$4

	#= TEST =#
	if [ "$id" == "6.1.8" ]; then
		[ $(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perms -0002  2> /dev/null | wc -l) -eq 0 ] && result="Pass"
	elif [ "$id" == "6.1.9" ]; then
		[ $(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nouser  2> /dev/null | wc -l) -eq 0 ] && result="Pass"
	elif [ "$id" == "6.1.10" ]; then
		[ $(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup 2> /dev/null | wc -l) -eq 0 ] && result="Pass"
	fi

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

## -- USER and GROUP SETTINGS -- ##
#Note: I ran out of ideals for naming my function so I will call it by id
function fn_6.2.0()
{
	local id
	level=$1
        chp=$2
        catid=$3
        id=$4

	[ $(awk -F: '($2 == "" )' /etc/shadow | wc -l) -eq 0 ] && result="Pass"

	 write_result "$level" "$chp" "$catid" "$id" "$result"

}

function no_legacy()
{
	local id file
	level=$1
        chp=$2
        catid=$3
        id=$4
	file=$5

	[ $(grep "^\+:" ${file} | wc -l) -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fn_6.2.2()
{
	local id score
	level=$1
        chp=$2
        catid=$3
        id=$4
	score=0

	#= TEST =#
	for x in $(echo $PATH | tr ":" " "); do
		if [ -d "$x" ]; then
			perm=$(ls -ldH "${x}")
			[ "$(echo $perm | awk '{print $9}')" != "${PWD}" ] || score=$((score+1))
			[ "$(echo $perm | awk '{print $3}')" == "root" ] || score=$((score+1))
			[ "$(echo $perm | cut -c6)" == "-" ] || score=$((score+1))
			[ "$(echo $perm | cut -c9)" == "-" ] || score=$((score+1))
		fi
	done

	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fn_6.2.5()
{
	local id
	level=$1
        chp=$2
        catid=$3
        id=$4

	#= TEST =#
	[ $(awk -F ":" '($3 == 0) {print}' /etc/passwd | wc -l) -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fn_6.2.6()
{
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4
	score=0

	#= TEST =#
	grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do

		if [ ! -d "$dir" ]; then
			score=$((score+1))
		else
			dirperm=$(ls -ld $dir | cut -f1 -d" ")

			[ $(echo $dirperm | cut -c6) == "-" ] || score=$((score+1))
			[ $(echo $dirperm | cut -c8) == "-" ] || score=$((score+1))
			[ $(echo $dirperm | cut -c9) == "-" ] || score=$((score+1))
			[ $(echo $dirperm | cut -c10) == "-" ] || score=$((score+1))

		fi

	done

	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fn_6.2.7()
{
	local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
	score=0

	grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
                
		if [ ! -d "$dir" ]; then
                        score=$((score+1))
		else
			owner=$(stat -L -c "%U" "$dir")
			[ "$owner" == "$user" ] || score=$((score+1))

		fi
	done

	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fn_6.2.8()
{
	local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
	score=0

	#= TEST =#
	grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do

		if [ ! -d "$dir" ]; then
			score=$((score+1))
		else
			for file in $dir/.[A-Za-z0-9]*;do
				if [ ! -h "$file" -a -f "$file" ]; then
					fileperm=$(ls -ld $file | cut -f1 -d" ")

					[ "$(echo $fileperm | cut -c6)" == "-" ] || score=$((score+1))
					[ "$(echo $fileperm | cut -c9)" == "-" ] || score=$((score+1))
				fi
			done
		fi
	done

	[ $score -eq 0 ] && result="Pass"
	
	 write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fn_6.2.9()
{
	local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        score=0

        #= TEST =#
        grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do

                if [ ! -d "$dir" ]; then
                        score=$((score+1))
                else
			if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
				score=$((score+1))		
			fi

		fi
	done

	[ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fn_6.2.10()
{
	local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        score=0

        #= TEST =#
        grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do

                if [ ! -d "$dir" ]; then
                        score=$((score+1))
                else
                        if [ ! -h "$dir/.netrc" -a -f "$idr/.netrc" ]; then
                                score=$((score+1))
                        fi

                fi
        done

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fn_6.2.11()
{
	local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        score=0

        #= TEST =#
        grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do

                if [ ! -d "$dir" ]; then
                        score=$((score+1))
                else
			for file in $dir/.netrc; do
				if [ ! -h "$file" -a -f "$file" ]; then
					fileperm=$(ls -ld $file |cut -f1 -d" ")

					[ $(echo $fileperm | cut -c5) == "-" ] || score=$((score+1))
					[ $(echo $fileperm | cut -c6) == "-" ] || score=$((score+1))
					[ $(echo $fileperm | cut -c7) == "-" ] || score=$((score+1))
					[ $(echo $fileperm | cut -c8) == "-" ] || score=$((score+1))
					[ $(echo $fileperm | cut -c9) == "-" ] || score=$((score+1))
					[ $(echo $fileperm | cut -c10) == "-" ] || score=$((score+1))

				fi
			done
		fi
	done

	[ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fn_6.2.12()
{
	local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        score=0

        #= TEST =#
        grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do

                if [ ! -d "$dir" ]; then
                        score=$((score+1))
                else
			for file in $dir/.rhosts; do
                        	if [ ! -h "$file" -a -f "$file" ]; then
                                	score=$((score+1))
                        	fi
			done

                fi
        done

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fn_6.2.13()
{
	local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        score=0

	#= TEST =#
	for i in $(cut -s -d: -f4 /etc/passwd | sort -u); do
		[ $(grep -q -P "^.*?:[^:]*:$i:" /etc/group &> /dev/null; echo $?) -eq 0 ] || score =$((score+1))
	done

	[ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fn_6.2.x()
{
	local id file para
	level=$1
        chp=$2
        catid=$3
        id=$4
	file=$5
	para=$6

	#function written for id 6.2.14 - 6.2.17

	#= TEST =#
	[ $(cut -f${para} -d: ${file} | sort | uniq -c | awk '$1 > 1 {print}' | wc -l) -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fn_6.2.18()
{
	local id score
	level=$1
        chp=$2
        catid=$3
        id=$4
	score=0 

	#= TEST =#
	shdw_gid=$( grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group | awk -F: '{print $3}')
	[ $( grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group | wc -l) -eq 0 ] && score=$((score+1))
	[ $(awk -F ":" '{$4 == "'$shdw_gid'"} {print}' /etc/passwd | wc -l) -eq 0 ] && score=$((score+1))

	[ $score -eq 2 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function fn_6.2.19()
{
	local id score
	level=$1
        chp=$2
        catid=$3
        id=$4
	score=0

	#= TEST =#
	grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do

		if [ ! -d "$dir" ]; then
			score=$((score+1))
		fi

	done

	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

	

	

		##---------- LEVEL 2 ----------##
		## -- CHAPTER ONE -- ##
##-- FILESYSTEM --##
function chk_partition() 
{
	local id
	level=$1
	chp=$2
	catid=$3
	id=$4
	partition=$5

	#description: Ensure separate partition exist for relevant partition

	#= TEST =#
	[ $(mount | grep "$partition" | wc -l) -ne 0 ] && result="Pass"
	
	write_result "$level" "$chp" "$catid" "$id" "$result"

}


##-- Mandatory Access Control (MAC) --##
function selinux_bootloader()
{
	local id
	level=$1
        chp=$2
        catid=$3
        id=$4

	#description: Ensure SELinux is not disable in bootloader configuration

	#= TEST =#
	[ $(grep -E 'kernelopts=(\S+\s+)*(selinux=0|enforcing=0)+\b' /boot/grub2/grubenv &> /dev/null; echo $?) -ne 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"
	
}

function unconfn_srv()
{
	local id
	level=$1
        chp=$2
        catid=$3
        id=$4

	#description: Ensure no unconfined services exist

	#=T TEST =#
	[ $(ps -eZ | grep unconfined_service_t &> /dev/null; echo $?) -ne 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function selinux_config()
{
	local id score
	level=$1
	chp=$2
	catid=$3
	id=$4
	score=0

	#description: Ensure SELinux policy is configured && state is enforcing]

	#= TEST =#
	if [ "$id" == "1.2.2" ]
	then
		[  $(grep -E '^\s*SELINUXTYPE=(targeted|mls)\b' /etc/selinux/config &> /dev/null; echo $?) -eq 0 ] && score=$((score+1))
		[ $(sestatus | grep Loaded | grep targeted &> /dev/null; echo $?) -eq 0 ] && score=$((score+1))
		[ $score -eq 2 ] && result="Pass"

	else
		[ $(grep -E '^\s*SELINUX=enforcing' /etc/selinux/config &> /dev/null; echo $?) -eq 0 ] &&score=$((score+1))
		[ $(sestatus | grep enforcing | wc -l) -ne 0 ] && score=$((score+1))
		[ $score -eq 2 ] && result="Pass"
	fi

	write_result "$level" "$chp" "$catid" "$id" "$result"

}


		## -- CHAPTER FOUR -- ##
##-- CONFIGURE SYSTEM ACCOUNTING --##
function audit_proc()
{
	local id var
	level=$1
        chp=$2
        catid=$3
        id=$4
	var=$5

	#= TEST =#
	[ $(grep -E "kernelopts=(\S+\s+)*$var\b" /boot/grub2/grubenv | wc -l) -ne 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function audit_conf1()
{
	local id score var
	level=$1
        chp=$2
        catid=$3
        id=$4
        var=$5
	score=0

	#= TEST =#
	if [[ "$id" == "4.1.5" ]]
	then
		[[ "$(grep $var /etc/audit/auditd.conf)" =~ "keep_logs" ]] || score=$((score+1))

	elif [[ "$id" == "4.1.6" ]]
	then
		[[ $(grep -E '^space_left_action' /etc/audit/auditd.conf | grep email | wc -l) -ne 0 ]] || score=$((score+1))
		[[ $(grep action_mail_acct /etc/audit/auditd.conf | grep root | wc -l) -ne 0 ]] || score=$((score+1))
		[[ $(grep admin_space_left_action /etc/audit/auditd.conf | grep halt | wc -l) -ne 0 ]] || score=$((score+1))

	else
		[ $(grep $var /etc/audit/auditd.conf | wc -l) -ne 0 ] || score=$((score+1))
	fi

	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function audit_conf2()
{
	local id score var regex
	level=$1
        chp=$2
        catid=$3
        id=$4
        var=$5
	regex=$6
        score=0

	#= TEST =#
	if [[ $regex -ne 1 ]]
	then
		[[ $(grep $var /etc/audit/rules.d/*.rules | wc -l) -ne 0 ]] || score=$((score+1))
		[[ $(auditctl -l | grep $var | wc -l) -ne 0 ]] || score=$((score+1))
		[[ $(grep $var /etc/audit/rules.d/*.rules | wc -l) -eq $(auditctl -l | grep $var | wc -l) ]] || score=$((score+1))

	else
		[[ $(grep -E "${var}" /etc/audit/rules.d/*.rules | wc -l) -ne 0 ]] || score=$((score+1))
		[[ $(auditctl -l | grep -E "${var}" | wc -l) -ne 0 ]] || score=$((score+1))
		[[ $(grep -E "${var}" /etc/audit/rules.d/*.rules | wc -l) -eq $(auditctl -l | grep -E "${var}" | wc -l) ]] || score=$((score+1))
	fi

	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function pcmd()
{
	local id part arr
	level=$1
        chp=$2
        catid=$3
        id=$4

	#description: Ensure use of privileged commands is collected
	#= TEST =#
	part=$(fdisk -l 2>/dev/null |awk '/^Disk \//{print substr($2,0,length($2)-1)}')
	arr=($part)

	for i in $(seq ${#arr[@]})
	do
		[ $(find "${arr[$i-1]}" -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' -F auid!=4294967295 -k privileged" }' | grep auditctl | wc -l) -ne 0 ] || score=$((score+1))
	done

	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function sulog_chk()
{
	local id score
	level=$1
        chp=$2
        catid=$3
        id=$4
	score=0

	#= TEST =#
	[ $(grep -E "^\s*-w\s+$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//')\s+-p\s+wa\s+-k\s+actions" /etc/audit/rules.d/*.rules | wc -l) -ne 0 ] || score=$((score+1))
	[[ "$(auditctl -l | grep actions)" =~ "-w /var/log/sudo.log -p wa -k actions" ]] || score=$((score+1))
	[[ "$(echo "-w $(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//') -p wa -k actions")" =~ "-w /var/log/sudo.log -p wa -k actions" ]] || score=$((score+1))

	[ $score -eq 0 ] && result="Pass"

	write_result "$level" "$chp" "$catid" "$id" "$result"

}

function audit_conf3()
{
	local id
	level=$1
        chp=$2
        catid=$3
        id=$4

	#description: Ensure the audit configuration is immutable

	#= TEST =#
	[ $(grep "^\s*[^#]" /etc/audit/rules.d/*.rules | grep -- "-e 2" | wc -l) -ne 0 ] && result="Pass"

	 write_result "$level" "$chp" "$catid" "$id" "$result"

}


if [ $# -eq 0 ]; then
	usage
	exit 1
fi



		##	Checking OPTIONS	##
while :; do
	case $1 in
		-h|--help)
			usage		#display the function usage
			exit 0
			;;
		-ls|--list)
			display		#list down the categories ID and name
			exit 0
			;;
		-l|--level)
			if [ ! -z "$2" ]; then
				lvl=$2
				shift
				shift
			else
				echo "Error: did not indicate the level."
				usage
				exit 1
			fi
			;;
		-e|--exclude)
			if [ $2 ]; then
				test_excluded $2
				shift
				shift
			else
				echo "Error: did not indicate the category id to be excluded from auditing."
				usage
				exit 1
			fi
			;;
		-vv|--verbose)
			verbose=1
			shift
			;;
		-sh|--show)
			show=1 #display result on table format 
			shift
			;;
		--)
			shift
			break
			;;
		*)
			break
	esac
done		

[ -z $lvl ] && all=1 #run both level 1 & 2 


banner		#Display the banner function
	
		###	Checking for Directories	###
write_info "Checking of $LOG_DIR..."
sleep $tos

if [ -d "$LOG_DIR" ] 
then
	write_debug "$LOG_DIR exists"
	if [ -d "$sub_logdir" ]
	then
		write_debug "$sub_logdir exists"
		sleep 0.25
	else
		write_debug "Creating $sub_logdir"
		mkdir "$sub_logdir"
		sleep 0.25
	fi

	if [ -d "$debug_dir" ]
	then
		write_debug "$debug_dir exists"
		sleep 0.25
	else
		write_debug "Creating $debug_dir"
		mkdir "$debug_dir"
	fi
		
else
	write_debug "Creating /var/log/centOS8_audit"
	mkdir "$LOG_DIR"

	write_debug "Creating subdirectories now...."
	sleep 0.5

	mkdir "$sub_logdir"
	write_debug "$sub_logdir is created"
	sleep 0.25

	mkdir "$debug_dir"
	write_debug "$sub_logdir is created"
	sleep 0.5

	write_info "Directories created..."
fi

		### Creating DEBUG FILE under debug directories	###

if [ -e "$debug_dir/$debug_file" ]
then
	write_debug "centos_debug.log exists"
else
	write_debug "Creating centos_debug.log"
	touch "$debug_dir/$debug_file"

	write_info "Debug file created..."
fi

		### Checking for JSON FILE	###

if [ -e "$JSN_DIR/$JSN_FIL" ]
then
	cp "$JSN_DIR/$JSN_FIL" "$JSN_DIR/${JSN_FIL}.old"

elif [ -e "$JSN_DIR/${JSN_FIL}.old" ]
then
	cp "$JSN_DIR/${JSN_FIL}.old" "$JSN_DIR/${JSN_FIL}"

else
	echo "$(date -Ins) [ERROR] centOS8.json does not exists"
	exit 1
fi


		###	 MAIN	 ### 
write_info "Initiating....."
write_info "Audit Test Starting"

if [[ $lvl -eq 1  ]] || [[ $all -eq 1 ]]
then
	##--LEVEL 1--##
	#chp. 1 INITIAL SETUP
	#catg: filesystem
	if [[ !("${excl_arr1[@]}" =~ "1.1") ]]; then
		run_test is_disabled 1 one 1.1 1.1.0 cramfs		#Ensure mounting of cramfs is disabled
		run_test is_disabled 1 one 1.1 1.1.1 squashfs 		#Ensure mounting of squashfs is disabled
		run_test is_disabled 1 one 1.1 1.1.2 udf 		#Ensure mounting of udf is disabled
		run_test tmp_config 1 one 1.1 1.1.3			#Ensure /tmp is configured
		run_test check_fs_option 1 one 1.1 1.1.4 /tmp 		#Ensure nodev, nosuid, noexec option set on /tmp partition 
		run_test check_fs_option 1 one 1.1 1.1.5 /var/tmp   	#Ensure nodev, nosuid, noexec option set on /var/tmp partition

		run_test not_scored 1 one 1.1 1.1.8			#Ensure nodev, nosuid, noexec option set on removable media partition
		run_test sticky_bit 1 one 1.1 1.1.9			#Ensure sticky bit is set on all world-writable directories
		run_test disable_automount 1 one 1.1 1.1.10		#Disable Automounting
		run_test is_disabled 1 one 1.1 1.1.11 usb-storage	#Ensure mounting of usb-storage is disabled
	fi
	
	#catg: software_update
	if [[ !("${excl_arr1[@]}" =~ "1.2") ]]; then
		run_test not_scored 1 one 1.2 1.2.0			#Ensure GPG keys are configured
		run_test gpg_check 1 one 1.2 1.2.1			#Ensure gpgcheck is globally activated
		run_test not_scored 1 one 1.2 1.2.2			#Ensure package manager repositories are configured
	fi

	#catg: sudo
	if [[ !("${excl_arr1[@]}" =~ "1.3") ]]; then
		run_test chkpkg_installed 1 one 1.3 1.3.0 sudo 1	#Ensure sudo is installed
		run_test check_pty 1 one 1.3 1.3.1			#Ensure sudo commands use pty
		run_test sudo_log 1 one 1.3 1.3.2			#Ensure sudo log file exists
	fi

	#catg: filesystem_integrity
	if [[ !("${excl_arr1[@]}" =~ "1.4") ]]; then
		run_test chkpkg_installed 1 one 1.4 1.4.0 aide 1	#Ensure AIDE is installed 
		run_test fs_periodic_check 1 one 1.4 1.4.1		#Ensure filesystem integirty is regularly
	fi

	#catg: secure_boot_settings
	if [[ !("${excl_arr1[@]}" =~ "1.5") ]]; then
		run_test boot_config 1 one 1.5 1.5.0			#Ensure permissions on bootloader config are configured
		run_test boot_passwd 1 one 1.5 1.5.1			#Ensure bootloader password is set
		run_test auth_single_usr 1 one 1.5 1.5.2		#Ensure authentication required for single user mode
	fi

	#catg: additional_process_hardening
	if [[ !("${excl_arr1[@]}" =~ "1.6") ]]; then
		run_test cd_restrict 1 one 1.6 1.6.0			#Ensure core dumps are restricted
		run_test alsr_enabled 1 one 1.6 1.6.1			#Ensure address space layout randomization is enabled
	fi
	
	#catg: motd
	if [[ !("${excl_arr1[@]}" =~ "1.7") ]]; then
		run_test motd_config 1 one 1.7 1.7.0 /etc/motd		#Ensure message and permissions on /etc/motd are configured properly
		run_test motd_config 1 one 1.7 1.7.1 /etc/issue		#Ensure message and permissions on /etc/issue are configured properly 
		run_test motd_config 1 one 1.7 1.7.2 /etc/issue.net	#Ensure message and permissions on /etc/issue.net are configured properly
		run_test gdm_config 1 one 1.7 1.7.3 			#Ensure GDM login banner is configured
		run_test not_scored 1 one 1.7 1.7.4			#Ensure updates, patches and additional security software
		run_test crypto_policy 1 one 1.7 1.7.5 1		#Ensure system-wide crypto policy is not legacy
	fi

	#----------------------------------#
	#chp. 2 SERVICES
	#catg: inetd services
	if [[ !("${excl_arr1[@]}" =~ "2.1") ]]; then
		run_test chkpkg_installed 1 two 2.1 2.1.0 xinetd 0 	#Ensure xinetd is not installed
	fi

	#catg: time synchronization
	if [[ !("${excl_arr1[@]}" =~ "2.2") ]]; then
		run_test not_scored 1 two 2.2 2.2.0		   	#Ensure time syncrhonization is in use
		run_test chrony_config 1 two 2.2 2.2.1		  	#Ensure chrony is configured
	fi

	#catg: Special Purpose Services
	if [[ !("${excl_arr1[@]}" =~ "2.3") ]]; then
		run_test chkpkg_installed 1 two 2.3 2.3.0 xorg-x11* 0	#Ensure X Window System is not installed
		run_test not_enabled 1 two 2.3 2.3.1 rsyncd		#Ensure Rsync service is not enabled 
		run_test not_enabled 1 two 2.3 2.3.2 avahi-daemon	#Ensure Avahi Server is not enabled
		run_test not_enabled 1 two 2.3 2.3.3 snmpd 		#Ensure SNMP Server is not enabled
		run_test not_enabled 1 two 2.3 2.3.4 squid		#Ensure HTTP Proxy Server is not enabled 
		run_test not_enabled 1 two 2.3 2.3.5 smb		#Ensure Samba is not enabled
		run_test not_enabled 1 two 2.3 2.3.6 dovecot		#Ensure IMAP & POP3 server is not enabled
		run_test not_enabled 1 two 2.3 2.3.7 httpd		#Ensure HTTP server is not enabled
		run_test not_enabled 1 two 2.3 2.3.8 vsftpd		#Ensure FTP server is not enabled
		run_test not_enabled 1 two 2.3 2.3.9 named		#Ensure DNS server is not enabled
		run_test not_enabled 1 two 2.3 2.3.10 nfs		#Enusre NFS is not enabled
		run_test not_enabled 1 two 2.3 2.3.11 rpcbind		#Ensure RPC is not enabled
		run_test not_enabled 1 two 2.3 2.3.12 slapd		#Ensure LDAP server is not enabled
		run_test not_enabled 1 two 2.3 2.3.13 dhcpd		#Ensure DHCP server is not enabled
		run_test not_enabled 1 two 2.3 2.3.14 cups		#Ensure CUPS is not enabled
		run_test not_enabled 1 two 2.3 2.3.15 ypserv		#Enusre NIS server is not enabled
		run_test mail_tagent 1 two 2.3 2.3.16 			#Ensure mail transfer agent is configured for local-only mode
	fi

	#catg: Service Clients
	if [[ !("${excl_arr1[@]}" =~ "2.4") ]]; then
		run_test chkpkg_installed 1 two 2.4 2.4.0 ypbind 0	#Ensure NIS Client is not installed
		run_test chkpkg_installed 1 two 2.4 2.4.1 telnet 0	#Ensure Telnet Client is not installed
		run_test chkpkg_installed 1 two 2.4 2.4.2 openldap-clients 0 #Ensure LDAP client is not installed
	fi

	#----------------------------------#
	#chp. 3 NETWORK CONFIGURATION
	#catg: network parameter (host only)
	if [[ !("${excl_arr1[@]}" =~ "3.1") ]]; then
		run_test sysctl_1 1 three 3.1 3.1.0 ip_forward 1 forwarding	#Ensure IP forwarding is disabled
		run_test sysctl_2 1 three 3.1 3.1.1 send_directs 0		#Ensure packet redirect sending is disabled
	fi
	
	#catg: network parameter (host and router)
	if [[ !("${excl_arr1[@]}" =~ "3.2") ]]; then
		run_test sysctl_2 1 three 3.2 3.2.0 accept_source_route 1	#Ensure source routed packets are not accepted
		run_test sysctl_2 1 three 3.2 3.2.1 secure_redirects 0		#Ensure ICMP redirects are not accepeted
		run_test sysctl_2 1 three 3.2 3.2.2 log_martians 0		#Ensure suspicious packets are logged
		run_test sysctl_1 1 three 3.2 3.2.3 icmp_echo_ignore_broadcasts 0 0	#Ensure broadcast ICMP requests are ignored
		run_test sysctl_1 1 three 3.2 3.2.4 icmp_ignore_bogus_error_responses 0 0 #Ensure bogus ICMP responses are ignored
		run_test sysctl_2 1 three 3.2 3.2.5 rp_filter 0			#Ensure Reverse Path Filtering is enabled
		run_test sysctl_1 1 three 3.2 3.2.6 tcp_syncookies 0		#Ensure TCP SYN Cookies is enabled
		run_test ipv6_route 1 three 3.2 3.2.7				#Ensure IPv6 route advertisements are not accepted
	fi

	#catg: firewall configuration
	if [[ !("${excl_arr1[@]}" =~ "3.3") ]]; then
		run_test fw_isinstall 1 three 3.3 3.3.0			#Ensure Firewall package is installed
		run_test fw_chkenabled 1 three 3.3 3.3.1 firewalld	#Ensure firewalld service is enabled and running
		run_test fw_chkenabled 1 three 3.3 3.3.2 nftables	#Ensure nftables is not enabled
		run_test default_zone 1 three 3.3 3.3.3			#Ensure default zone is set
		run_test not_scored 1 three 3.3 3.3.4			#Ensure unnecessary services and ports are not accepted
		run_test not_scored 1 three 3.3 3.3.5			#Ensure network interface are assigned to appropriate zone
		run_test fw_chkenabled 1 three 3.3 3.3.6 iptables	#Ensure iptables is not enabled
		run_test not_scored 1 three 3.3 3.3.7			#Ensure iptables are flushed
		run_test nft_1 1 three 3.3 3.3.8 tables			#Ensure a table exists
		run_test nft_2 1 three 3.3 3.3.9 	 		#Ensure base chains exist
		run_test nft_3 1 three 3.3 3.3.10.1			#Ensure loopback traffic is configured - 1.1
		run_test chk_iptables 1 three 3.3 3.3.10.2 loopback 	#Ensure loopback traffic is configured - 1.2
		run_test not_scored 1 three 3.3 3.3.11.1		#Ensure outbound and established connections are configured - 1.1
       		run_test not_scored 1 three 3.3 3.3.11.2		#Ensure outbound and established connections are configured - 1.2
		run_test nft_2 1 three 3.3 3.3.12.1 drop		#Ensure default deny firewall policy - 1.1
		run_test chk_iptables 1 three 3.3 3.3.12.2 null 	#Ensure default deny firewall policy - 1.2
		run_test is_enabled 1 three 3.3 3.3.13 nftables		#Ensure nftables service is enabled
		run_test nftrul_perm 1 three 3.3 3.3.14			#Ensure nftables rules are permanent
		run_test fwll_op 1 three 3.3 3.3.15			#Ensure firewall rules exist for all open ports
		run_test chk_ip6tables 1 three 3.3 3.3.16		#Ensure IPV6 default deny firewall policy
		run_test chk_ip6tables 1 three 3.3 3.3.17 loopback	#Ensure IPv6 default deny firewall policy
		run_test not_scored 1 three 3.3 3.3.18			#Ensure IPv6 outbound and established connections are configured
		run_test not_scored 1 three 3.3 3.3.19			#Ensure IPv6 firewall rules exists for all open ports
	fi

	#catg: wireless configuration
	if [[ !("${excl_arr1[@]}" =~ "3.4") ]]; then
		run_test wifi_config 1 three 3.4 3.4.0			#Ensure wireless interfaces are disabled
	fi

	#----------------------------------#
	#chp. 4 LOGGING AND AUDITING
	#catg: configure logging
	if [[ !("${excl_arr1[@]}" =~ "4.1") ]]; then
		run_test chkpkg_installed 1 four 4.1 4.1.0 rsyslog 1	#Ensure rsyslog is installed
		run_test is_enabled 1 four 4.1 4.1.1 rsyslog		#Ensure rsyslog service is enabled
		run_test rsyslog_perm 1 four 4.1 4.1.2 			#Ensure rsyslog default file permissions configured
		run_test not_scored 1 four 4.1 4.1.3			#Ensure logging is configured
		run_test send_log 1 four 4.1 4.1.4			#Ensure rsyslog is configured to send logs to a remoate log host
		run_test not_scored 1 four 4.1 4.1.5			#Ensure remote rsyslog messages are only accepted on designated log hosts
		run_test journald_cfg 1 four 4.1 4.1.6			#Ensure journald is configured to send logs to rsyslog
		run_test journald_cfg 1 four 4.1 4.1.7			#Ensure journald is configured to compress large log files
		run_test journald_cfg 1 four 4.1 4.1.8 			#Ensure journald is configured to write logfiles to persistent disk
	fi
	
	#catg: log rotation
	if [[ !("${excl_arr1[@]}" =~ "4.2") ]]; then
		run_test not_scored 1 four 4.2 4.2.0			#Ensure logrotate is configured
	fi

	#----------------------------------#
	#chp. 5 ACCESS, AUTHENTICATION AND AUTHORIZATION
	#catg: configure cron
	if [[ !("${excl_arr1[@]}" =~ "5.1") ]]; then
		run_test is_enabled 1 five 5.1 5.1.0 crond		#Ensure cron daemon is enabled
		run_test cron_perm1 1 five 5.1 5.1.1 tab		#Ensure permissions on /etc/crontab are configured
		run_test cron_perm1 1 five 5.1 5.1.2 .hourly		#Ensure permissions on /etc/cron.hourly are configured
		run_test cron_perm1 1 five 5.1 5.1.3 .daily		#Ensure permissions on /etc/cron.daily are configured
		run_test cron_perm1 1 five 5.1 5.1.4 .weekly		#Ensure permissions on /etc/cron.weekly are configured
		run_test cron_perm1 1 five 5.1 5.1.5 .monthly		#Ensure permissions on /etc/cron.monthly are configured
		run_test cron_perm1 1 five 5.1 5.1.6 .d			#Enusre permissions on /etc/cron.d are configured
		run_test cron_perm2 1 five 5.1 5.1.7			#Ensure at /cron is restricted to authorized users
	fi

	#catg: ssh server configuration
	if [[ !("${excl_arr1[@]}" =~ "5.2") ]]; then
		run_test ssh_perm 1 five 5.2 5.2.0			#Ensure permissions on /etc/ssh/sshd_config are configured
		run_test ssh_cfg_3 1 five 5.2 5.2.1			#Ensure SSH access is limited
		run_test ssh_key_config 1 five 5.2 5.2.2 0		#Ensure permissions on SSH private host key files are configured
		run_test ssh_key_config 1 five 5.2 5.2.3 1		#Ensure permissions on SSH public host key files are configured
		run_test ssh_cfg_1 1 five 5.2 5.2.4 loglevel "(INFO|VERBOSE)"   #Ensure SSH LogLevel is appropriate
		run_test ssh_cfg_1 1 five 5.2 5.2.5 x11forwarding no		#Ensure SSH X11 forwarding is disabled
		run_test ssh_cfg_1 1 five 5.2 5.2.6 maxauthtries "[1-4]"	#Ensure SSH MaxAuthTries is set to 4 or less
		run_test ssh_cfg_1 1 five 5.2 5.2.7 ignorerhosts yes		#Ensure SSH IgnoreRhost is enabled
		run_test ssh_cfg_1 1 five 5.2 5.2.8 hostbasedauthentication no	#Ensure SSH HostbasedAuthentication is disabled
		run_test ssh_cfg_1 1 five 5.2 5.2.9 permitrootlogin no		#Ensure SSH root login is disabled
		run_test ssh_cfg_1 1 five 5.2 5.2.10 permitemptypasswords no	#Ensure SSH PermitEmptyPasswords is disabled
		run_test ssh_cfg_1 1 five 5.2 5.2.11 permituserenvironment no	#Ensure SSH PermitUserEnvironment is disabled
		run_test ssh_cfg_2 1 five 5.2 5.2.12 clientaliveinternal clientalivecountmax 300 0	#Ensure SSH Idle Timeout Interval is configured
		run_test ssh_cfg_1 1 five 5.2 5.2.13 logingracetime "[1-60]"	#Ensure SSH LoginGraceTime is set to one minute or less
		run_test ssh_cfg_1 1 five 5.2 5.2.14 banner issue.net		#Ensure SSH warnning banner is configured
		run_test ssh_cfg_1 1 five 5.2 5.2.15 usepam yes			#Ensure SSH PAM is enabled
		run_test ssh_cfg_1 1 five 5.2 5.2.16 maxstartups 10:30:60	#Ensure SSH MaxStartups is configured
		run_test ssh_cfg_1 1 five 5.2 5.2.17 maxsessions "[1-4]"	#Ensure SSH MaxSessions is set to 4 or less
		run_test ssh_crypto 1 five 5.2 5.2.18			#Ensure system-wide crypto policy is not over-ridden
	fi

	#catg: configure authselect
	if [[ !("${excl_arr1[@]}" =~ "5.3") ]]; then
		run_test auth_custom 1 five 5.3 5.3.0			#Create custom authselect profile
       		run_test auth_profile 1 five 5.3 5.3.1			#Select authselect profile
		run_test auth_flck 1 five 5.3 5.3.2			#Ensure authselect includes with-faillock
	fi

	#catg: configure pam	
	if [[ !("${excl_arr1[@]}" =~ "5.4") ]]; then
		run_test pam_config 1 five 5.4 5.4.0			#Ensure password creation requirements are configured
		run_test pam_config 1 five 5.4 5.4.1			#Ensure lockout for failed password attempts is configured
		run_test pam_config 1 five 5.4 5.4.2			#Ensure password reuse is limited
		run_test pam_config 1 five 5.4 5.4.3			#Ensure password hashing algorithm is SHA-512
	fi

	#catg: user accounts and environment
	if [[ !("${excl_arr1[@]}" =~ "5.5") ]]; then
		run_test uae_cfg 1 five 5.5 5.5.0 ^PASS_MAX_DAYS 365 5	#Ensure password expiration is 365 days or less
		run_test uae_cfg 1 five 5.5 5.5.1 ^PASS_MIN_DAYS 7 4	#Ensure minimum days between password changes is 7 or more 
		run_test uae_cfg 1 five 5.5 5.5.2 ^PASS_WARN_AGE 7 6	#Ensure password expiration warning days is 7 or more 
		run_test uae_cfg 1 five 5.5 5.5.3 INACTIVE 30 7		#Ensure inactive password lock is 30 days or less
		run_test pwd_cfg 1 five 5.5 5.5.4			#Ensure all users last password change date is in the past
		run_test sysacc_secured	1 five 5.5 5.5.5		#Ensure system accounts are secured
		run_test def_usr_shell 1 five 5.5 5.5.6			#Ensure default user shell timeout is 900 seconds or less
		run_test def_grp_access 1 five 5.5 5.5.7		#Ensure default group for the root account is GID 0
		run_test def_usr_umask 1 five 5.5 5.5.8			#Ensure default user umake is 027 or more restrictive
	fi
	
	#catg: root login configuration
	if [[ !("${excl_arr1[@]}" =~ "5.6") ]]; then
		run_test not_scored 1 five 5.6 5.6.0			#Ensure root login is restricted to system console
	fi
	
	#catg: su command
	if [[ !("${excl_arr1[@]}" =~ "5.7") ]]; then
		run_test su_access 1 five 5.7 5.7.0			#Ensure access to su command is restricted
	fi

	#----------------------------------#
	#chp. 6 SYSTEM MAINTENANCE
	#catg: system file permissions
	if [[ !("${excl_arr1[@]}" =~ "6.1") ]]; then
		run_test file_perm 1 six 6.1 6.1.0 /etc/passwd 0644		#Ensure permissions on /etc/passwd are configured
		run_test file_perm 1 six 6.1 6.1.1 /etc/shadow "0[0-6][0|4]0"	#Ensure permissions on /etc/shadow are configured
		run_test file_perm 1 six 6.1 6.1.2 /etc/group 0644		#Ensure permissions on /etc/group are configured
		run_test file_perm 1 six 6.1 6.1.3 /etc/gshadow "0[0-6][0|4]0"	#Ensure permissions on /etc/gshadow are configured
		run_test file_perm 1 six 6.1 6.1.4 /etc/passwd-	"0[0-6]00"	#Ensure permissions on /etc/passwd- are configured
       		run_test file_perm 1 six 6.1 6.1.5 /etc/shadow- "0[0-6][0|4]0"	#Ensure permissions on /etc/shadow- are configured
		run_test file_perm 1 six 6.1 6.1.6 /etc/group- "0[0-6][0|4][0|4]" #Ensure permissions on /etc/group- are configured
		run_test file_perm 1 six 6.1 6.1.7 /etc/gshadow- "0[0-6][0|4]0"	#Ensure permissions on /etc/gshadow- are configured
		run_test no_exist 1 six 6.1 6.1.8 			#Ensure no world writable files exist
		run_test no_exist 1 six 6.1 6.1.9 			#Ensure no unowned file or directories exist
		run_test no_exist 1 six 6.1 6.1.10 			#Ensure no ungrouped files or directories exist
		run_test not_scored 1 six 6.1 6.1.11			#Audit SUID executables
		run_test not_scored 1 six 6.1 6.1.12			#Audit SGID executables
	fi

	#catg: user and group settings
	if [[ !("${excl_arr1[@]}" =~ "6.2") ]]; then
		run_test fn_6.2.0 1 six 6.2 6.2.0			#Ensure password fields are not empty
		run_test no_legacy 1 six 6.2 6.2.1 /etc/passwd		#Ensure no legacy "+" entries exist in /etc/passwd
		run_test fn_6.2.2 1 six 6.2 6.2.2			#Ensure root PATH Integrity 
		run_test no_legacy 1 six 6.2 6.2.3 /etc/shadow		#Enusre no legacy "+" entries exist in /etc/shadow
		run_test no_legacy 1 six 6.2 6.2.4 /etc/group		#Ensure no legacy "+" entries exist in /etc/group
		run_test fn_6.2.5 1 six 6.2 6.2.5			#Ensure root is the only UID 0 account
		run_test fn_6.2.6 1 six 6.2 6.2.6			#Ensure user's home directories permissions are 750 or more restrictive
		run_test fn_6.2.7 1 six 6.2 6.2.7			#Ensure users own their home directories
		run_test fn_6.2.8 1 six 6.2 6.2.8			#Ensure user's odt files are not group or world writable
		run_test fn_6.2.9 1 six 6.2 6.2.9			#Ensure no users have .forward files
		run_test fn_6.2.10 1 six 6.2 6.2.10			#Ensure no users have .netrc files
		run_test fn_6.2.11 1 six 6.2 6.2.11			#Ensure user's netrc file are not group or world accessible
		run_test fn_6.2.12 1 six 6.2 6.2.12			#Ensure no users have .rhosts files
		run_test fn_6.2.13 1 six 6.2 6.2.13			#Ensure all groups in /etc/passwd exist in /etc/group
		run_test fn_6.2.x 1 six 6.2 6.2.14 /etc/passwd 3	#Enusre no duplicate UIDs exist	
		run_test fn_6.2.x 1 six 6.2 6.2.15 /etc/group 3		#Ensure no duplicate GIDs exist
		run_test fn_6.2.x 1 six 6.2 6.2.16 /etc/passwd 1	#Ensure no duplicate user names exist
		run_test fn_6.2.x 1 six 6.2 6.2.17 /etc/group 1		#Ensure no duplicate group names exist
		run_test fn_6.2.18 1 six 6.2 6.2.18			#Ensure shadow group is empty
		run_test fn_6.2.19 1 six 6.2 6.2.19			#Ensure all user's home directories exist
	fi

fi


	##########################################################################################
	##########################################################################################

if [[ $lvl -eq 2 ]] || [[ $all -eq 1 ]]
then

	##--LEVEL 2--##
	#chp. 1 INITIAL SETUP
	#catg: filesystem
	if [[ !("${excl_arr2[@]}" =~ "1.1") ]]; then
		run_test not_scored 2 one 1.1 1.1.0			#Ensure mounting of vFAT filesystem is limited
		run_test chk_partition 2 one 1.1 1.1.1 /var		#Ensure separate partition exists for /var
	       	run_test chk_partition 2 one 1.1 1.1.2 /var/tmp		#Ensure separate partition exists for /var/tmp
		run_test chk_partition 2 one 1.1 1.1.3 /var/log/audit 	#Ensure separate partition exists for /var/log/audit
		run_test chk_partition 2 one 1.1 1.1.4 /home		#Ensure separate partition exists for /home
		run_test is_disabled 2 one 1.1 1.1.5 usb-storage	#Disable USB Storage	
	fi
	
	#catg: MAC
	if [[ !("${excl_arr2[@]}" =~ "1.2") ]]; then
		run_test chkpkg_installed 2 one 1.2 1.2.0 libselinux 1	#Ensure SELinux is installed
		run_test selinux_bootloader 2 one 1.2 1.2.1		#Ensure SELinux is not disable in bootloader configuration
		run_test selinux_config 2 one 1.2 1.2.2			#Ensure SELinux policy is configured
		run_test selinux_config 2 one 1.2 1.2.3			#Ensure the SELinux state is enforcing
		run_test unconfn_srv 2 one 1.2 1.2.4			#Ensure no unconfined services exist
		run_test chkpkg_installed 2 one 1.2 1.2.5 setroubleshoot 0 #Ensure SETroubleshoot is not installed
		run_test chkpkg_installed 2 one 1.2 1.2.6 mcstrans 0	#Ensure the MCS Translation Services (mcstrans) is not installed
		run_test crypto_policy 2 one 1.3 1.3.0 0		#Ensure system-wide crypto policy is FUTURE or FIPS
	fi

	#----------------------------------#
	#chp. 3 NETWORK CONFIGURATION
	#catg: uncommon network protocol
	if [[ !("${excl_arr2[@]}" =~ "3.1") ]]; then
		run_test is_disabled 2 three 3.1 3.1.0 dccp		#Ensure DCCP is disabled
		run_test is_disabled 2 three 3.1 3.1.1 sctp		#Ensure SCTP is disabled
		run_test is_disabled 2 three 3.1 3.1.2 rds		#Ensure RDS is disabled
		run_test is_disabled 2 three 3.1 3.1.3 tipc		#Ensure TIPC is disabled 
	fi

	#catg: wireless configuration
	if [[ !("${excl_arr2[@]}" =~ "3.2") ]]; then
		run_test wifi_config 2 three 3.2 3.2.0			#Ensure wireless interfaces are disabled
	fi

	#catg: disable ipv6
	if [[ !("${excl_arr2[@]}" =~ "3.3") ]]; then
		run_test not_scored 2 three 3.3 3.3.0			#Disable IPv6
	fi

	#----------------------------------#
	#chp. 4 LOGGING AND AUDITING
	#catg: configure system accounting
	if [[ !("${excl_arr2[@]}" =~ "4.1") ]]; then
		run_test chkpkg_installed 2 four 4.1 4.1.0 "audit audit-libs" 1 #Ensure auditd is installed
		run_test is_enabled 2 four 4.1 4.1.1 auditd			#Ensure auditd service is enabled
		run_test audit_proc 2 four 4.1 4.1.2 "audit=1"			#Ensure auditing for processes that start prior to auditd
		run_test audit_proc 2 four 4.1 4.1.3 "audit_backlog_limit=\S+"  #Ensure audit_backlog_limit is sufficient
		run_test audit_conf1 2 four 4.1 4.1.4 max_log_file		#Ensure audit log storage size is configured
		run_test audit_conf1 2 four 4.1 4.1.5 max_log_file_action	#Ensure audit log storage size is configured
		run_test audit_conf1 2 four 4.1 4.1.6 				#Ensure system is disabled when audit logs are full

		run_test audit_conf2 2 four 4.1 4.1.9 "'(session|logins)'" 1	#Ensure session initiation information is collected
		run_test audit_conf2 2 four 4.1 4.1.10 time-change 0		#Ensure events that modify date and time information are collected
		run_test audit_conf2 2 four 4.1 4.1.11 MAC-policy 0		#Ensure events that modify the system's Mandotry Access Controls are collected
		run_test audit_conf2 2 four 4.1 4.1.12 system-locale 0		#Ensure events that modify the system's network environment are collected
		run_test audit_conf2 2 four 4.1 4.1.13 perm_mod 0		#Ensure discretionary access control permission modification events are collected
		run_test audit_conf2 2 four 4.1 4.1.14 access 0			#Ensure unsuccessful unauthorized file access attempts are collected
		run_test audit_conf2 2 four 4.1 4.1.15 identity 0		#Ensure events that modify user/group information are collected
		run_test audit_conf2 2 four 4.1 4.1.16 mounts 0			#Ensure successful file system mounts are collected
		run_test pcmd 2 four 4.1 4.1.17					#Ensure use of privileged commands is collected
		run_test audit_conf2 2 four 4.1 4.1.18 delete 0			#Ensure file deletion events by users are collected
		run_test audit_conf2 2 four 4.1 4.1.19 modules			#Ensure kernel module loading and unloading is collected
		run_test sulog_chk 2 four 4.1 4.1.20				#Ensure system administrator actions (sudolog) are collected
		run_test audit_conf3 2 four 4.1 4.1.21				#Ensure the audit configuration is immutable
	fi

	#----------------------------------#
	#chp. 5 ACCESS, AUTHENTICATION AND AUTHORIZATION
	if [[ !("${excl_arr2[@]}" =~ "5.1") ]]; then
		run_test ssh_cfg_1 2 five 5.1 5.1.0 allowtcpforwarding no	#Ensure SSH AllowTcpForwarding is disabled
	fi
	
	#----------------------------------#
	#chp. 6 SYSTEM MAINTENANCE
	if [[ !("${excl_arr2[@]}" =~ "6.1") ]]; then
		run_test not_scored 2 six 6.1 6.1.0			#Audit system file permissions
	fi
fi

write_info "Audit Test is done"
write_info "Script exited"
echo "Done..."
echo "-------------------------------------------------"
echo " "

if [[ $show -eq 1 ]]; then
        retrieve "${lvl}" "${all}"
fi

rename "$JSN_DIR" "$JSN_FIL"

unset excl_arr1
unset excl_arr2
