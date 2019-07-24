#!/bin/bash
red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`

if [ "$1" = "" ]; then
    echo ${red}ERROR: Agent database required
    echo Usage: ./test-sca-policies.sh \<agent-database.db\>${reset}
    exit 1
fi

echo "" > /var/ossec/logs/ossec.log
rm  $1*
/var/ossec/bin/ossec-control restart

# Wait until database is created
sleep 5

output=$(sqlite3 $1 "select * from sca_check" | wc -l)

while [ $output -le 0 ]
do
    output=$(sqlite3 $1 "select * from sca_check" | wc -l)
    sleep 1
done

sqlite3 $1 "select * from sca_check" > sca_database.txt

current_policy_id=""
failed_checks=0
passed_checks=0

while IFS= read -r line
do
    policy_id=$(echo $line | cut -d'|' -f 3)
    if [ "$policy_id" != "$current_policy_id" ]; then
        echo Testing policy $policy_id
        current_policy_id=$policy_id
    fi

    check_id=$(echo $line | cut -d'|' -f 2)
    obtained_result=$(echo $line | rev | cut -d'|' -f 3 | rev)

    if [ "$obtained_result" = "" ]; then
        obtained_result=$(echo $line | rev | cut -d'|' -f 2 | rev)
    fi

    if [ "$obtained_result" != "passed" ]; then
        echo ${red}Check $check_id result: NOT OK${reset} expected result: passed, ${red}obtained result: $obtained_result ${reset}
        failed_checks=$((failed_checks+1))
    else
        echo ${green}Check $check_id result: OK${reset} expected result: passed, obtained result: $obtained_result
        passed_checks=$((passed_checks+1))
    fi

done < sca_database.txt

rm sca_database.txt

printf "\n\nRESULTS:\n"
echo "Failed checks: $failed_checks"
echo "Passed checks: $passed_checks"
