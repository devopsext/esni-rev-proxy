#!/bin/bash
if [[ -z $(uname -a | grep -i darwin) ]]; then
	echo  "This script is developed to run under MacOS..."
	exit 1
fi	

settings='user_pref("network.trr.mode",2); user_pref("network.security.esni.enabled",true); user_pref("network.trr.uri","https://doh.opendns.com/dns-query");'

profilesFolder="${HOME}/Library/Application Support/Firefox"
profiles=$(grep Path "${profilesFolder}/profiles.ini" | cut -c6- | xargs)

for profile in $profiles; do
	profilePath="${profilesFolder}/${profile}"
	echo " => Processing profile '$profilePath'..."
	for feature in $settings; do
		if [[ ! -f "${profilePath}/user.js" ]] || [[ -z $(grep -i "$feature" "${profilePath}/user.js" ) ]]; then
			echo "$feature" >> "${profilePath}/user.js"
		fi	
	done	
done
