#!/bin/bash
red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`


if [ $# -ne 2 ]; then
    echo ${red}ERROR: Agent database and policy test required. Type 1 in case you want to check policy tests or 0 otherwise.
    echo Usage: ./test-sca-policies.sh \<agent-database.db\> \<test-policies\>
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

    if [ $2 -eq 0 ]; then
        if [ "$obtained_result" != "passed" ]; then
            echo ${red}Check $check_id result: NOT OK${reset} expected result: passed, ${red}obtained result: $obtained_result ${reset}
            failed_checks=$((failed_checks+1))
        else
            echo ${green}Check $check_id result: OK${reset} expected result: passed, obtained result: $obtained_result
            passed_checks=$((passed_checks+1))
        fi
    else
        expected_result=$(echo $line | cut -d'|' -f 4 | cut -d' ' -f 1)
        if [ "$expected_result" = "INVALID" ]; then
            if [ "$obtained_result" = "Not applicable" ]; then
                echo ${green}Check $check_id result: OK ${reset}expected result: $expected_result, obtained result: $obtained_result
                passed_checks=$((passed_checks+1))
            else
                echo ${red}Check $check_id result: NOT OK ${reset}expected result: $expected_result, ${red}obtained result: $obtained_result${reset}
                failed_checks=$((failed_checks+1))
            fi
        elif [ "$expected_result" = "PASS" ]; then
            if [ "$obtained_result" = "passed" ]; then
                echo ${green}Check $check_id result: OK ${reset}expected result: $expected_result, obtained result: $obtained_result
                passed_checks=$((passed_checks+1))
            else
                echo ${red}Check $check_id result: NOT OK ${reset}expected result: $expected_result, ${red}obtained result: $obtained_result${reset}
                failed_checks=$((failed_checks+1))
            fi
        elif [ "$expected_result" = "FAIL" ]; then
            if [ "$obtained_result" = "failed" ]; then
                echo ${green}Check $check_id result: OK ${reset}expected result: $expected_result, obtained result: $obtained_result
                passed_checks=$((passed_checks+1))
            else
                echo ${red}Check $check_id result: NOT OK ${reset}expected result: $expected_result, ${red}obtained result: $obtained_result${reset}
                failed_checks=$((failed_checks+1))
            fi
        else
            echo ${red}Check $check_id. Couldn\'t get expected result ${reset}
        fi
    fi

done < sca_database.txt

rm sca_database.txt

printf "\n\nRESULTS:\n"
echo "Failed checks: $failed_checks"
echo "Passed checks: $passed_checks"
