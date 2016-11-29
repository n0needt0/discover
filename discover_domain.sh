#!/bin/bash
#
# by Lee Baird
# Contact me via chat or email with any feedback or suggestions that you may have:
# leebaird@gmail.com
#
# Special thanks to the following people:
#
# Jay Townsend - conversion from Backtrack to Kali, manages pull requests & issues
# Jason Ashton (@jayw0k)- Penetration Testers Framework (PTF) compatibility, bug crusher
# Ian Norden (@iancnorden) - new report framework design
#
# Ben Wood (@DilithiumCore) - regex master
# Dave Klug - planning, testing and bug reports
# Jason Arnold (@jasonarnold) - planning original concept, author of ssl-check and co-author of crack-wifi
# John Kim - python guru, bug smasher, and parsers
# Eric Milam (@Brav0Hax) - total re-write using functions
# Martin Bos (@cantcomputer) - IDS evasion techniques
# Matt Banick - original development
# Numerous people on freenode IRC - #bash and #sed (e36freak)
# Rob Dixon (@304geek) - report framework idea
# Robert Clowser (@dyslexicjedi)- all things
# Saviour Emmanuel - Nmap parser
# Securicon, LLC. - for sponsoring development of parsers
# Steve Copland - initial report framework design

##############################################################################################################

# Catch process termination
trap f_terminate SIGHUP SIGINT SIGTERM

if [ $# -eq 0 ]
  then
    echo "domain required .. ./discover_domain.sh domain.com"
    exit
fi

# Global variables
export domain=$1
IFS='.' read -ra NAMES <<< "$1"
export company=${NAMES[0]}

echo "Starting Discovery for $domain and $company"

discover=$(updatedb; locate discover_domain.sh | sed 's:/[^/]*$::')
distro=$(uname -n)
home=$HOME
long='========================================================================================================='
medium='==============================================================='
short='========================================'

sip='sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'

browser=Firefox
ip=$(ip addr | grep 'global' | cut -d '/' -f1 | awk '{print $2}')
interface=$(ip link | awk '{print $2, $9}' | grep 'UP' | cut -d ':' -f1)
msf=msfconsole
msfv=msfvenom
port=443
web="firefox -new-tab"

##############################################################################################################

f_terminate(){

save_dir=$home/data/cancelled-`date +%H:%M:%S`
echo "Terminating..."
echo "All data will be saved in $save_dir"
mkdir $save_dir

# Nmap and Metasploit scans
mv $name/ $save_dir 2>/dev/null

# Recon files
mv curl emails* names* networks* records squatting network-tools whois* sub* doc pdf ppt txt xls tmp* z* $save_dir 2>/dev/null
rm /tmp/emails /tmp/names /tmp/networks /tmp/profiles /tmp/subdomains 2>/dev/null

echo "Saving complete"
exit
}

##############################################################################################################

f_domain(){

     # If folder doesn't exist, create it
     if [ ! -d $home/data/$domain ]; then
          cp -R $discover/report/ $home/data/$domain
          sed 's/REPLACEDOMAIN/'$domain'/g' $home/data/$domain/index.htm > tmp
          mv tmp $home/data/$domain/index.htm
     fi

     # Number of tests
     total=33

     companyurl=$( printf "%s\n" "$company" | sed 's/ /%20/g;s/\&/%26/g;s/\,/%2C/g' )

     echo
     echo $medium
     echo
     echo "ARIN"
     echo "     Email                (1/$total)"
     wget -q https://whois.arin.net/rest/pocs\;domain=$domain -O tmp.xml

     # Remove all empty files
     find -type f -empty -exec rm {} +

     if [ -e tmp.xml ]; then
          xmllint --format tmp.xml | grep 'handle' | cut -d '>' -f2 | cut -d '<' -f1 | sort -u > zurls.txt
          xmllint --format tmp.xml | grep 'handle' | cut -d '"' -f2 | sort -u > zhandles.txt

          while read x; do
               wget -q $x -O tmp2.xml
               xml_grep 'email' tmp2.xml --text_only >> zarin-emails
          done < zurls.txt
     fi

     echo "     Names                (2/$total)"
     if [ -e zhandles.txt ]; then
          while read y; do
               curl --silent https://whois.arin.net/rest/poc/$y.txt | grep 'Name' >> tmp
          done < zhandles.txt

          grep -v '@' tmp | sed 's/Name:           //g' | tr '[A-Z]' '[a-z]' | sed 's/\b\(.\)/\u\1/g' | sort -u > zarin-names
     fi

     rm zurls.txt zhandles.txt 2>/dev/null

     echo "     Networks             (3/$total)"

     wget -q https://whois.arin.net/rest/orgs\;name=$companyurl -O tmp.xml

     if [ -s tmp.xml ]; then
          xmllint --format tmp.xml | grep 'handle' | cut -d '/' -f6 | cut -d '<' -f1 | sort -uV > tmp

          while read handle; do
               echo "          " $handle
               curl --silent https://whois.arin.net/rest/org/$handle/nets.txt | head -1 > tmp2
               if grep 'DOCTYPE' tmp2 > /dev/null; then
                    echo > /dev/null
               else
                    awk '{print $4 "-" $6}' tmp2 >> tmp3
               fi
          done < tmp
     fi

     $sip tmp3 > networks-tmp 2>/dev/null
     echo

     echo "dnsrecon                  (4/$total)"
     dnsrecon -d $domain -t goo > tmp
     grep $domain tmp | egrep -v '(Performing|Records Found)' | awk '{print $3 " " $4}' | awk '$2 !~ /[a-z]/' | column -t | sort -u > sub1
     echo

     echo "theHarvester"
     # PTF
     if [ -f /pentest/intelligence-gathering/theharvester/theHarvester.py ]; then
          theharvester="theharvester"
     else
          theharvester="python /usr/share/theharvester/theHarvester.py"
     fi

     echo "     Baidu                (9/$total)"
     $theharvester -d $domain -b baidu > zbaidu
     echo "     Bing                 (10/$total)"
     $theharvester -d $domain -b bing > zbing
     echo "     Dogpilesearch        (11/$total)"
     $theharvester -d $domain -b dogpilesearch > zdogpilesearch
     echo "     Google               (12/$total)"
     $theharvester -d $domain -b google > zgoogle
     echo "     Google CSE           (13/$total)"
     $theharvester -d $domain -b googleCSE > zgoogleCSE
     echo "     Google+              (14/$total)"
     $theharvester -d $domain -b googleplus | sed 's/ - Google+//g' > zgoogleplus
     echo "     Google Profiles	  (15/$total)"
     $theharvester -d $domain -b google-profiles > zgoogle-profiles
     echo "     Jigsaw               (16/$total)"
     $theharvester -d $domain -b jigsaw > zjigsaw
     echo "     LinkedIn             (17/$total)"
     $theharvester -d $domain -b linkedin > zlinkedin
     echo "     PGP                  (18/$total)"
     $theharvester -d $domain -b pgp > zpgp
     echo "     Yahoo                (19/$total)"
     $theharvester -d $domain -b yahoo > zyahoo
     echo "     All                  (20/$total)"
     $theharvester -d $domain -b all > zall
     echo

     echo "Metasploit                (21/$total)"
     msfconsole -x "use auxiliary/gather/search_email_collector; set DOMAIN $domain; run; exit y" > tmp 2>/dev/null
     grep @$domain tmp | awk '{print $2}' | grep -v '%' | grep -Fv '...@' > zmsf
     echo

     echo "URLCrazy                  (22/$total)"
     urlcrazy $domain > tmp
     # Clean up & Remove Blank Lines
     egrep -v '(#|:|\?|\-|RESERVED|URLCrazy)' tmp | sed '/^$/d' > tmp2
     # Realign Columns
     sed -e 's/..,/   /g' tmp2 > tmp3
     # Convert Caps
     sed 's/AUSTRALIA/Australia/g; s/AUSTRIA/Austria/g; s/BAHAMAS/Bahamas/g; s/BANGLADESH/Bangladesh/g; s/BELGIUM/Belgium/g; s/CANADA/Canada/g; s/CAYMAN ISLANDS/Cayman Islands/g; s/CHILE/Chile/g; s/CHINA/China/g; s/COSTA RICA/Costa Rica/g; s/CZECH REPUBLIC/Czech Republic/g; s/DENMARK/Denmark/g; s/EUROPEAN UNION/European Union/g; s/FINLAND/Finland/g; s/FRANCE/France/g; s/GERMANY/Germany/g; s/HONG KONG/Hong Kong/g; s/HUNGARY/Hungary/g; s/INDIA/India/g; s/IRELAND/Ireland/g; s/ISRAEL/Israel/g; s/ITALY/Italy/g; s/JAPAN/Japan/g; s/KOREA REPUBLIC OF/Republic of Korea/g; s/LUXEMBOURG/Luxembourg/g; s/NETHERLANDS/Netherlands/g; s/NORWAY/Norway/g; s/POLAND/Poland/g; s/RUSSIAN FEDERATION/Russia            /g; s/SAUDI ARABIA/Saudi Arabia/g; s/SPAIN/Spain/g; s/SWEDEN/Sweden/g; s/SWITZERLAND/Switzerland/g; s/TAIWAN REPUBLIC OF China (ROC)/Taiwan                        /g; s/THAILAND/Thailand/g; s/TURKEY/Turkey/g; s/UKRAINE/Ukraine/g; s/UNITED KINGDOM/United Kingdom/g; s/UNITED STATES/United States/g; s/VIRGIN ISLANDS (BRITISH)/Virgin Islands          /g; s/ROMANIA/Romania/g; s/SLOVAKIA/Slovakia/g' tmp3 > squatting

     ##############################################################

     cat z* > tmp
     # Remove lines that contain a number
     sed '/[0-9]/d' tmp > tmp2
     # Remove lines that start with @
     sed '/^@/ d' tmp2 > tmp3
     # Remove lines that start with .
     sed '/^\./ d' tmp3 > tmp4
     # Change to lower case
     cat tmp4 | tr '[A-Z]' '[a-z]' > tmp5
     # Remove blank lines
     sed '/^$/d' tmp5 > tmp6
     # Remove lines that contain a single word
     sed '/[[:blank:]]/!d' tmp6 > tmp7
     # Clean up
     egrep -v '(\*|\[|:|found|full)' tmp7 | sort -u > names1

     ##############################################################

     cat z* | sed '/^[0-9]/!d' | grep -v '@' > tmp
     # Substitute a space for a colon
     sed 's/:/ /g' tmp > tmp2
     # Move the second column to the first position
     awk '{ print $2 " " $1 }' tmp2 > tmp3
     column -t tmp3 > tmp4
     # Change to lower case
     cat tmp4 | tr '[A-Z]' '[a-z]' > tmp5
     sed 's/<strong>//g; s/<//g' tmp5 | grep $domain | column -t | sort -u > sub2
     echo

     ##############################################################

     echo "Whois"
     echo "     Domain               (23/$total)"
     whois -H $domain > tmp 2>/dev/null
     # Remove leading whitespace
     sed 's/^[ \t]*//' tmp > tmp2
     # Clean up
     egrep -v '(#|%|<a|=-=-=-=|Access may be|Additionally|Afilias except|and DNS Hosting|and limitations of|any use of|Be sure to|By submitting an|by the terms|can easily change|circumstances will|clientDeleteProhibited|clientTransferProhibited|clientUpdateProhibited|company may be|complaint will|contact information|Contact us|Copy and paste|currently set|database|data contained in|data presented in|date of|dissemination|Domaininfo AB|Domain Management|Domain names in|Domain status: ok|enable high|except as reasonably|failure to|facsimile of|for commercial purpose|for detailed information|For information for|for information purposes|for the sole|Get Noticed|Get a FREE|guarantee its|HREF|In Europe|In most cases|in obtaining|in the address|includes restrictions|including spam|information is provided|is not the|is providing|Learn how|Learn more|makes this information|MarkMonitor|mining this data|minute and one|modify existing|modify these terms|must be sent|name cannot|NamesBeyond|not to use|Note: This|NOTICE|obtaining information about|of Moniker|of this data|or hiding any|or otherwise support|other use of|own existing customers|Please be advised|Please note|policy|prior written consent|privacy is|Problem Reporting System|Professional and|prohibited without|Promote your|protect the|Public Interest|queries or|Register your|Registrars|registration record|repackaging,|responsible for|See Business Registration|server at|solicitations via|sponsorship|Status|support questions|support the transmission|telephone, or facsimile|that apply to|that you will|the right| The data is|The fact that|the transmission|The Trusted Partner|This listing is|This feature is|This information|This service is|to collect or|to entities|to report any|transmission of mass|UNITED STATES|United States|unsolicited advertising|Users may|Version 6|via e-mail|Visit AboutUs.org|while believed|will use this|with many different|with no guarantee|We reserve the|Whois|you agree|You may not)' tmp2 > tmp3
     # Remove lines starting with "*"
     sed '/^*/d' tmp3 > tmp4
     # Remove lines starting with "-"
     sed '/^-/d' tmp4 > tmp5
     # Remove lines starting with http
     sed '/^http/d' tmp5 > tmp6
     # Remove lines starting with US
     sed '/^US/d' tmp6 > tmp7
     # Clean up phone numbers
     sed 's/+1.//g' tmp7 > tmp8
     # Remove leading whitespace from file
     awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp8 > tmp9
     # Remove trailing whitespace from each line
     sed 's/[ \t]*$//' tmp9 > tmp10
     # Compress blank lines
     cat -s tmp10 > tmp11
     # Remove lines that end with various words then a colon or period(s)
     egrep -v '(2:$|3:$|Address.$|Address........$|Address.........$|Ext.:$|FAX:$|Fax............$|Fax.............$|Province:$|Server:$)' tmp11 > tmp12
     # Remove line after "Domain Servers:"
     sed -i '/^Domain Servers:/{n; /.*/d}' tmp12
     # Remove line after "Domain servers"
     sed -i '/^Domain servers/{n; /.*/d}' tmp12
     # Remove blank lines from end of file
     awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp12 > tmp13

     while IFS=$': \t' read -r first rest; do
          if [[ $first$rest ]]; then
               printf '%-20s %s\n' "$first:" "$rest"
          else
               echo
          fi
     done < tmp13 > whois-domain

     echo "     IP 		  (24/$total)"
     wget -q http://network-tools.com/default.asp?prog=network\&host=$domain -O network-tools
     y=$(cat network-tools | grep 'Registered Domain' | awk '{print $1}')

     if ! [ "$y" = "" ]; then
          whois -H $y > tmp
          # Remove leading whitespace
          sed 's/^[ \t]*//' tmp > tmp2
          # Remove trailing whitespace from each line
          sed 's/[ \t]*$//' tmp2 > tmp3
          # Clean up
          egrep -v '(\#|\%|\*|All reports|Comment|dynamic hosting|For fastest|For more|Found a referral|http|OriginAS:$|Parent:$|point in|RegDate:$|remarks:|The activity|the correct|this kind of object|Without these)' tmp3 > tmp4
          # Remove leading whitespace from file
          awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp4 > tmp5
          # Remove blank lines from end of file
          awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp5 > tmp6
          # Compress blank lines
          cat -s tmp6 > tmp7
          # Clean up
          sed 's/+1-//g' tmp7 > tmp8
          while IFS=$': \t' read -r first rest; do
               if [[ $first$rest ]]; then
                    printf '%-20s %s\n' "$first:" "$rest"
               else
                    echo
               fi
          done < tmp8 > whois-ip
          echo

          # Remove all empty files
          find -type f -empty -exec rm {} +
     else
          echo > whois-ip
     fi

     echo "dnsdumpster.com           (25/$total)"
     wget -q https://dnsdumpster.com/static/map/$domain.png -O /tmp/dnsdumpster.png
     wget -q https://dnsdumpster.com/static/map/$domain.png -O $home/data/$domain/images/dnsdumpster.png

     # Generate a random cookie value
     rando=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

     curl --silent --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$rando&targetip=$domain" --cookie "csrftoken=$rando; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com > tmp

     dumpsterxls=$(grep 'xls' tmp | tr '"' ' ' | cut -d ' ' -f10)
     wget -q $dumpsterxls -O tmp.xlsx

     ssconvert -E Gnumeric_Excel:xlsx -T Gnumeric_stf:stf_csv tmp.xlsx tmp.csv 2>/dev/null
     cat tmp.csv | sed 's/,"//g' | egrep -v '(Hostname|MX|NS)' | cut -d ',' -f1-2 | grep -v '"' | sed 's/,/ /g' | sort -u | column -t > sub-dnsdumpster

     echo "dnswatch.info             (26/$total)"
     echo '*' > tmp
     echo '%' >> tmp

     # A record
     wget -q https://www.dnswatch.info/dns/dnslookup?la=en\&host=$domain\&type=A\&submit=Resolve -O tmp2
     grep 'A record found' tmp2 | sed 's/">/ /g' | sed 's/<\// /g' | awk '{print $6","$1","" "}' >> tmp

     # NS records
     wget -q https://www.dnswatch.info/dns/dnslookup?la=en\&host=$domain\&type=NS\&submit=Resolve -O tmp2
     grep 'NS record found' tmp2 | sed 's/\.</>/g' | cut -d '>' -f2 > tmp3
     while read i; do wget -q http://network-tools.com/default.asp?prog=network\&host=$i -O network-tools; grep 'Registered Domain' network-tools | awk '{print $1",""NS"","host}' host="$i" >> tmp; done < tmp3

     # MX Records
     wget -q https://www.dnswatch.info/dns/dnslookup?la=en\&host=$domain\&type=MX\&submit=Resolve -O tmp2
     grep 'MX record found' tmp2 | sed 's/\.</ /g' | cut -d ' ' -f6 > tmp3
     while read i; do wget -q http://network-tools.com/default.asp?prog=network\&host=$i -O network-tools; grep 'Registered Domain' network-tools | awk '{print $1",""MX"","host}' host="$i" >> tmp; done < tmp3

     # SOA records
     wget -q https://www.dnswatch.info/dns/dnslookup?la=en\&host=$domain\&type=SOA\&submit=Resolve -O tmp2
     grep 'SOA record found' tmp2 | sed 's/>/ /g' | sed 's/\. / /g' | cut -d ' ' -f6 > tmp3
     grep 'SOA record found' tmp2 | sed 's/>/ /g' | sed 's/\. / /g' | cut -d ' ' -f7 >> tmp3
     while read i; do wget -q http://network-tools.com/default.asp?prog=network\&host=$i -O network-tools; grep 'Registered Domain' network-tools | awk '{print $1",""SOA"","host}' host="$i" >> tmp; done < tmp3

     # TXT records
     wget -q https://www.dnswatch.info/dns/dnslookup?la=en\&host=$domain\&type=TXT\&submit=Resolve -O tmp2
     grep 'TXT record found' tmp2 | sed 's/>&quot;/%/g' | sed 's/&quot;</%/g' | sed 's/TXT/%TXT%/g' | awk -F'%' '{print " "","$2","$4}' >> tmp

     # Formatting & clean-up
     column -s ',' -t tmp > tmp4

     egrep -v '(\*|%)' tmp4 >> $home/data/$domain/data/records.htm
     echo >> $home/data/$domain/data/records.htm
     echo '</body>' >> $home/data/$domain/data/records.htm
     echo >> $home/data/$domain/data/records.htm
     echo '</html>' >> $home/data/$domain/data/records.htm

     echo "email-format.com          (27/$total)"
     curl --silent http://www.email-format.com/d/$domain/ | grep -o [A-Za-z0-9_.]*@[A-Za-z0-9_.]*[.][A-Za-z]* > zemail-format

     echo "ewhois.com                (28/$total)"
     wget -q http://www.ewhois.com/$domain/ -O tmp
     cat tmp | grep 'visitors' | cut -d '(' -f1 | cut -d '>' -f2 | grep -v 'OTHER' | column -t | sort -u > sub3

     echo "intodns.com               (29/$total)"
     wget -q http://www.intodns.com/$domain -O tmp
     cat tmp | sed '1,32d' | sed 's/<table width="99%" cellspacing="1" class="tabular">/<center><table width="85%" cellspacing="1" class="tabular"><\/center>/g' | sed 's/Test name/Test/g' | sed 's/ <a href="feedback\/?KeepThis=true&amp;TB_iframe=true&amp;height=300&amp;width=240" title="intoDNS feedback" class="thickbox feedback">send feedback<\/a>//g' | egrep -v '(Processed in|UA-2900375-1|urchinTracker|script|Work in progress)' | sed '/footer/I,+3 d' | sed '/google-analytics/I,+5 d' > tmp2
     cat tmp2 >> $home/data/$domain/pages/config.htm

     echo "netcraft.com              (31/$total)"
     wget -q http://toolbar.netcraft.com/site_report?url=http://$domain -O tmp

     # Remove lines from FOO to the second BAR
     awk '/DOCTYPE/{f=1} (!f || f>2){print} (f && /\/form/){f++}' tmp > tmp2

     egrep -v '(Background|Hosting country|the-world-factbook)' tmp2 | sed 's/Refresh//g' > tmp3

     # Find lines that contain FOO, and delete to the end of file
     sed '/security_table/,${D}' tmp3 | sed 's/<h2>/<h4>/g' | sed 's/<\/h2>/<\/h4>/g' > tmp4

     # Compress blank lines
     sed /^$/d tmp4 >> $home/data/$domain/pages/netcraft.htm
     echo >> $home/data/$domain/pages/netcraft.htm
     echo '</body>' >> $home/data/$domain/pages/netcraft.htm
     echo >> $home/data/$domain/pages/netcraft.htm
     echo '</html>' >> $home/data/$domain/pages/netcraft.htm

     echo "ultratools.com            (32/$total)"
     x=0

     f_passive_axfr(){
          sed -e 's/<[^>]*>//g' curl > tmp
          grep -A4 "\<.*$domain\>" tmp | sed 's/--//g' | sed 's/\.$//g' | sed 's/^ *//g' | sed '/^$/d' > tmp2
          cat tmp2 | paste - - - - - -d, | column -s ',' -t > tmp3
          sort -u tmp3 >> $home/data/$domain/data/zonetransfer.htm
          echo >> $home/data/$domain/data/zonetransfer.htm
     }

     while [ $x -le 10 ]; do
          curl -k --silent https://www.ultratools.com/tools/zoneFileDumpResult?zoneName=$domain > curl
          q=$(grep "$domain" curl | wc -l)
          if [ $q -gt 1 ]; then
               f_passive_axfr
               break
          else
               x=$(( $x + 1 ))
               sleep 2
          fi
     done

     if [ $x -eq 11 ]; then
          echo 'Zone transfer failed.' >> $home/data/$domain/data/zonetransfer.htm
     fi

     echo '</body>' >> $home/data/$domain/data/zonetransfer.htm
     echo >> $home/data/$domain/data/zonetransfer.htm
     echo '</html>' >> $home/data/$domain/data/zonetransfer.htm

     echo "recon-ng                  (33/$total)"
     cp $discover/resource/recon-ng.rc $discover/
     sed -i "s/xxx/$companyurl/g" $discover/recon-ng.rc
     sed -i 's/%26/\&/g;s/%20/ /g;s/%2C/\,/g' $discover/recon-ng.rc
     sed -i "s/yyy/$domain/g" $discover/recon-ng.rc
     recon-ng --no-check -r $discover/recon-ng.rc

     grep "@$domain" /tmp/emails | awk '{print $2}' | egrep -v '(>|SELECT)' > tmp
     grep "@$domain" /tmp/profiles | awk '{print $2}' > tmp2
     cat tmp tmp2 | sort -u > emails-recon

     grep '/' /tmp/networks | grep -v 'Spooling' | awk '{print $2}' | $sip > networks-recon
     grep "$domain" /tmp/subdomains | grep -v '>' | awk '{print $2,$4}' | column -t > sub-recon

     grep '|' /tmp/names | awk '{print $2", "$4}' | egrep -v '(_|\|)' | tr '[A-Z]' '[a-z]' | sed 's/\b\(.\)/\u\1/g' > tmp
     grep '|' /tmp/profiles | awk '{print $3", "$2}' | grep -v '|' > tmp2
     cat tmp tmp2| sort -u > names-recon

     ##############################################################

     cat z* | grep "@$domain" | grep -vF '...' | grep -Fv '..' | egrep -v '(%|\*|-|=|\+|\[|\]|\||;|:|"|<|>|/|\?|,,|alphabetagency|anotherfed|definetlynot|edsnowden|edward.snowden|edward_snowden|esnowden|fake|fuckthepolice|jesus.juice|lastname_firstname|regulations|salessalesandmarketing|superspy|toastmasters|www|x.y|xxxxx|yousuck|zxcvbcvxvxcccb)' > tmp
     # Remove trailing whitespace from each line
     sed 's/[ \t]*$//' tmp > tmp2
     # Remove lines that start with a number
     sed '/^[0-9]/d' tmp2 > tmp3
     # Remove lines that start with @
     sed '/^@/ d' tmp3 > tmp4
     # Remove lines that start with .
     sed '/^\./ d' tmp4 > tmp5
     # Remove lines that start with _
     sed '/^\_/ d' tmp5 > tmp6
     # Change to lower case
     cat tmp6 emails-recon | grep -v "'" | tr '[A-Z]' '[a-z]' | sort -u > emails

     ##############################################################

     cat names1 names-recon > tmp
     # Remove lines that contain a number
     sed '/[0-9]/d' tmp > tmp2
     # Remove lines that start with @
     sed '/^@/ d' tmp2 > tmp3
     # Remove lines that start with .
     sed '/^\./ d' tmp3 > tmp4
     # Change to lower case
     cat tmp4 | tr '[A-Z]' '[a-z]' > tmp5
     # Remove blank lines
     sed '/^$/d' tmp5 > tmp6
     # Remove lines that contain a single word
     sed '/[[:blank:]]/!d' tmp6 > tmp7
     # Clean up
     egrep -v '(~|`|!|@|#|\$|%|\^|&|\*|\(|\)|_|-|\+|=|{|\[|}|]|\|:|;|"|<|>|\.|\?|/|abuse|academy|account|achievement|acquisition|acting|action|active|adjuster|admin|advanced|adventure|advertising|agency|alliance|allstate|ambassador|america|american|analysis|analyst|analytics|animal|another|antivirus|apple seems|application|applications|architect|archivist|article|assembler|assembling|assembly|asian|assignment|assistant|associate|association|attorney|audience|audio|auditor|australia|authority|automation|automotive|aviation|balance|bank|bbc|beginning|berlin|beta theta|between|big game|billion|bioimages|biometrics|bizspark|breaches|broker|builder|business|buyer|buying|california|cannot|capital|career|carrying|cashing|center|certified|cfi|challenger|championship|change|chapter|charge|chemistry|china|chinese|claim|class|clearance|cloud|cnc|code|cognitive|college|columbia|coming|commercial|communications|community|company pages|competition|competitive|compliance|computer|comsec|concept|conference|config|connections|connect|construction|consultant|contact|contract|contributor|control|cooperation|coordinator|corporate|corporation|counsel|create|creative|critical|crm|croatia|cryptologic|custodian|cyber|dallas|database|day care|dba|dc|death toll|delivery|delta|department|deputy|description|designer|design|destructive|detection|develop|devine|dialysis|digital|diploma|direct|disability|disaster|disclosure|dispatch|dispute|distribut|divinity|division|dns|document|dos poc|download|driver|during|economy|ecovillage|editor|education|effect|electronic|else|email|embargo|emerging|empower|employment|end user|energy|engineer|enterprise|entertainment|entreprises|entrepreneur|entry|environmental|error page|ethical|example|excellence|executive|expertzone|exploit|facebook|facilit|faculty|failure|fall edition|fast track|fatherhood|fbi|federal|fellow|filmmaker|finance|financial|fitter|forensic|forklift|found|freelance|from|frontiers in tax|fulfillment|full|function|future|fuzzing|germany|get control|global|google|governance|government|graphic|greater|group|guard|hackers|hacking|harden|harder|hawaii|hazing|headquarters|health|help|history|homepage|hospital|hostmaster|house|how to|hurricane|icmp|idc|in the news|index|infant|inform|innovation|installation|insurers|integrated|intellectual|international|internet|instructor|insurance|intelligence|interested|investigation|investment|investor|israel|items|japan|job|justice|kelowna|knowing|language|laptops|large|leader|letter|level|liaison|licensing|lighting|linguist|linkedin|limitless|liveedu|llp|local|looking|lpn|ltd|lsu|luscous|machinist|macys|malware|managed|management|manager|managing|manufacturing|market|mastering|material|mathematician|maturity|md|mechanic|media|medical|medicine|member|merchandiser|meta tags|methane|metro|microsoft|middle east|migration|mission|mitigation|mn|money|monitor|more coming|mortgage|motor|museums|mutual|national|negative|network|network|new user|newspaper|new york|next page|night|nitrogen|nw|nyc|obtain|occupied|offers|office|online|onsite|operations|operator|order|organizational|outbreak|owner|packaging|page|palantir|paralegal|partner|pathology|peace|people|perceptions|person|pharmacist|philippines|photo|picker|picture|placement|places|planning|police|portfolio|postdoctoral|potassium|potential|preassigned|preparatory|president|principal|print|private|process|producer|product|professional|professor|profile|project|program|property|publichealth|published|pyramid|quality|questions|rcg|recruiter|redeem|redirect|region|register|registry|regulation|rehab|remote|report|representative|republic|research|resolving|responsable|restaurant|retired|revised|rising|rural health|russia|sales|sample|satellite|save the date|school|scheduling|science|scientist|search|searc|sections|secured|security|secretary|secrets|see more|selection|senior|server|service|services|social|software|solution|source|special|sql|station home|statistics|store|strategy|strength|student|study|substitute|successful|sunoikisis|superheroines|supervisor|support|surveillance|switch|system|systems|talent|targeted|tax|tcp|teach|technical|technician|technique|technology|temporary|tester|textoverflow|theater|thought|through|time in|tit for tat|title|toolbook|tools|toxic|traditions|trafficking|transfer|transformation|treasury|trojan|truck|twitter|training|ts|tylenol|types of scams|unclaimed|underground|underwriter|university|united states|untitled|vault|verification|vietnam|view|Violent|virginia bar|voice|volkswagen|volume|vp|wanted|web search|web site|website|welcome|west virginia|westchester|when the|whiskey|window|worker|world|www|xbox|zz)' tmp7 > tmp8
     sed 's/iii/III/g' tmp8 | sed 's/ii/II/g' > tmp9
     # Capitalize the first letter of every word
     sed 's/\b\(.\)/\u\1/g' tmp9 | sed 's/Mca/McA/g; s/Mcb/McB/g; s/Mcc/McC/g; s/Mcd/McD/g; s/Mce/McE/g; s/Mcf/McF/g; s/Mcg/McG/g; s/Mci/McI/g; s/Mck/McK/g; s/Mcl/McL/g; s/Mcm/McM/g; s/Mcn/McN/g; s/Mcs/McS/g; s/,,/,/g' > tmp10
     grep -v ',' tmp10 | awk '{print $2", "$1}' > tmp11
     grep ',' tmp10 > tmp12
     # Remove trailing whitespace from each line
     cat tmp11 tmp12 | sed 's/[ \t]*$//' | sort -u > names

     ##############################################################

     cat networks-tmp networks-recon | sort -u | $sip > networks

     cat sub* | grep -v "$domain\." | grep -v '|' | sed 's/www\.//g' | column -t | tr '[A-Z]' '[a-z]' | sort -u > tmp
     # Remove lines that contain a single word
     sed '/[[:blank:]]/!d' tmp > subdomains

     awk '{print $2}' subdomains > tmp
     grep -E '([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})' tmp | egrep -v '(-|=|:)' | $sip > hosts

     if [ -e networks ]; then
          cat networks > tmp 2>/dev/null
          echo >> tmp
     fi

     cat hosts >> tmp 2>/dev/null
     cat tmp >> $home/data/$domain/data/hosts.htm; echo "</pre>" >> $home/data/$domain/data/hosts.htm 2>/dev/null

     ##############################################################

     echo "Summary" > zreport
     echo $short >> zreport

     echo > tmp

     if [ -e emails ]; then
          emailcount=$(wc -l emails | cut -d ' ' -f1)
          echo "Emails        $emailcount" >> zreport
          echo "Emails ($emailcount)" >> tmp
          echo $short >> tmp
          cat emails >> tmp
          echo >> tmp
          cat emails >> $home/data/$domain/data/emails.htm
     fi

     if [ -e names ]; then
          namecount=$(wc -l names | cut -d ' ' -f1)
          echo "Names         $namecount" >> zreport
          echo "Names ($namecount)" >> tmp
          echo $short >> tmp
          cat names >> tmp
          echo >> tmp
          cat names >> $home/data/$domain/data/names.htm
     fi

     if [ -s networks ]; then
          networkcount=$(wc -l networks | cut -d ' ' -f1)
          echo "Networks      $networkcount" >> zreport
          echo "Networks ($networkcount)" >> tmp
          echo $short >> tmp
          cat networks >> tmp
          echo >> tmp
     fi

     if [ -e hosts ]; then
          hostcount=$(wc -l hosts | cut -d ' ' -f1)
          echo "Hosts         $hostcount" >> zreport
          echo "Hosts ($hostcount)" >> tmp
          echo $short >> tmp
          cat hosts >> tmp
          echo >> tmp
     fi

     if [ -e squatting ]; then
          urlcount2=$(wc -l squatting | cut -d ' ' -f1)
          echo "Squatting     $urlcount2" >> zreport
          echo "Squatting ($urlcount2)" >> tmp
          echo $long >> tmp
          cat squatting >> tmp
          echo >> tmp
          cat squatting >> $home/data/$domain/data/squatting.htm
     fi

     if [ -e subdomains ]; then
          urlcount=$(wc -l subdomains | cut -d ' ' -f1)
          echo "Subdomains    $urlcount" >> zreport
          echo "Subdomains ($urlcount)" >> tmp
          echo $long >> tmp
          cat subdomains >> tmp
          echo >> tmp
          cat subdomains >> $home/data/$domain/data/subdomains.htm
     fi

     if [ -e xls ]; then
          xlscount=$(wc -l xls | cut -d ' ' -f1)
          echo "Excel         $xlscount" >> zreport
          echo "Excel Files ($xlscount)" >> tmp
          echo $long >> tmp
          cat xls >> tmp
          echo >> tmp
          cat xls >> $home/data/$domain/data/xls.htm; echo "</pre>" >> $home/data/$domain/data/xls.htm
     fi

     if [ -e pdf ]; then
          pdfcount=$(wc -l pdf | cut -d ' ' -f1)
          echo "PDF           $pdfcount" >> zreport
          echo "PDF Files ($pdfcount)" >> tmp
          echo $long >> tmp
          cat pdf >> tmp
          echo >> tmp
          cat pdf >> $home/data/$domain/data/pdf.htm; echo "</pre>" >> $home/data/$domain/data/pdf.htm
     fi

     if [ -e ppt ]; then
          pptcount=$(wc -l ppt | cut -d ' ' -f1)
          echo "PowerPoint    $pptcount" >> zreport
          echo "PowerPoint Files ($pptcount)" >> tmp
          echo $long >> tmp
          cat ppt >> tmp
          echo >> tmp
          cat ppt >> $home/data/$domain/data/ppt.htm; echo "</pre>" >> $home/data/$domain/data/ppt.htm
     fi

     if [ -e txt ]; then
          txtcount=$(wc -l txt | cut -d ' ' -f1)
          echo "Text          $txtcount" >> zreport
          echo "Text Files ($txtcount)" >> tmp
          echo $long >> tmp
          cat txt >> tmp
          echo >> tmp
          cat txt >> $home/data/$domain/data/txt.htm; echo "</pre>" >> $home/data/$domain/data/txt.htm
     fi

     if [ -e doc ]; then
          doccount=$(wc -l doc | cut -d ' ' -f1)
          echo "Word          $doccount" >> zreport
          echo "Word Files ($doccount)" >> tmp
          echo $long >> tmp
          cat doc >> tmp
          echo >> tmp
          cat doc >> $home/data/$domain/data/doc.htm; echo "</pre>" >> $home/data/$domain/data/doc.htm
     fi

     cat tmp >> zreport

     if [ -e whois-domain ]; then
          echo "Whois Domain" >> zreport
          echo $long >> zreport
          cat whois-domain >> zreport
          cat whois-domain >> $home/data/$domain/data/whois-domain.htm; echo "</pre>" >> $home/data/$domain/data/whois-domain.htm
     fi

     if [ -e whois-ip ]; then
          echo "Whois IP" >> zreport
          echo $long >> zreport
          cat whois-ip >> zreport
          cat whois-ip >> $home/data/$domain/data/whois-ip.htm; echo "</pre>" >> $home/data/$domain/data/whois-ip.htm
     fi

     echo "</pre>" >> $home/data/$domain/data/names.htm
     echo "</pre>" >> $home/data/$domain/data/squatting.htm
     echo "</pre>" >> $home/data/$domain/data/subdomains.htm

     cat zreport >> $home/data/$domain/data/passive-recon.htm; echo "</pre>" >> $home/data/$domain/data/passive-recon.htm

     mv recon-ng.rc $home/data/$domain/ 2>/dev/null
     rm curl debug* emails* hosts names* networks* squatting sub* tmp* network-tools whois* z* doc pdf ppt txt xls 2>/dev/null
     rm /tmp/emails /tmp/names /tmp/networks /tmp/profiles /tmp/subdomains 2>/dev/null

     # Robtex
     wget -q https://www.robtex.com/gfx/graph.png?dns=$domain -O $home/data/$domain/images/robtex.png

     # If folder doesn't exist, create it
     if [ ! -d $home/data/$domain ]; then
          cp -R $discover/report/ $home/data/$domain
          sed 's/REPLACEDOMAIN/'$domain'/g' $home/data/$domain/index.htm > tmp
          mv tmp $home/data/$domain/index.htm
     fi

     # Number of tests
     total=11

     companyurl=$( printf "%s\n" "$company" | sed 's/ /%20/g;s/\&/%26/g;s/\,/%2C/g' )

     echo
     echo $medium
     echo

     echo "Nmap"
     echo "     Email                (1/$total)"
     nmap -Pn -n --open -p80 --script=http-grep $domain > tmp
     grep '@' tmp | awk '{print $3}' > emails1

     echo
     echo "dnsrecon"
     echo "     DNS Records          (2/$total)"
     dnsrecon -d $domain -t std > tmp
     egrep -v '(All queries|Bind Version for|Could not|Enumerating SRV|It is resolving|not configured|Performing|Records Found|Recursion|Resolving|TXT|Wildcard)' tmp > tmp2
     # Remove first 6 characters from each line
     sed 's/^......//g' tmp2 | awk '{print $2,$1,$3,$4,$5,$6,$7,$8,$9,$10}' | column -t | sort -u -k2 -k1 > tmp3
     grep 'TXT' tmp | sed 's/^......//g' | awk '{print $2,$1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15}' >> tmp3
     egrep -v '(SEC3|SKEYs|SSEC)' tmp3 > records
     cat $home/data/$domain/data/records.htm records | grep -v '<' | column -t | sort -u -k2 -k1 > tmp3

     echo '<pre style="font-size:14px;">' > $home/data/$domain/data/records.htm
     cat tmp3 | column -t >> $home/data/$domain/data/records.htm; echo "</pre>" >> $home/data/$domain/data/records.htm

     echo "     Zone Transfer        (3/$total)"
     dnsrecon -d $domain -t axfr > tmp
     egrep -v '(Checking for|Failed|filtered|NS Servers|Removing|TCP Open|Testing NS)' tmp | sed 's/^....//g' | sed /^$/d > zonetransfer

     echo "     Sub-domains (~5 min) (4/$total)"
     if [ -f /usr/share/dnsrecon/namelist.txt ]; then
          dnsrecon -d $domain -t brt -D /usr/share/dnsrecon/namelist.txt --iw -f > tmp
     fi

     # PTF
     if [ -f /pentest/intelligence-gathering/dnsrecon/namelist.txt ]; then
          dnsrecon -d $domain -t brt -D /pentest/intelligence-gathering/dnsrecon/namelist.txt --iw -f > tmp
     fi

     grep $domain tmp | grep -v "$domain\." | egrep -v '(Performing|Records Found)' | sed 's/\[\*\] //g; s/^[ \t]*//' | awk '{print $2,$3}' | column -t | sort -u > subdomains-dnsrecon

     echo
     echo "Fierce (~5 min)           (5/$total)"
     if [ -f /usr/share/fierce/hosts.txt ]; then
          fierce -dns $domain -wordlist /usr/share/fierce/hosts.txt -suppress -file tmp4
     fi

     # PTF
     if [ -f /pentest/intelligence-gathering/fierce/hosts.txt ]; then
          fierce -dns $domain -wordlist /pentest/intelligence-gathering/fierce/hosts.txt -suppress -file tmp4
     fi

     sed -n '/Now performing/,/Subnets found/p' tmp4 | grep $domain | awk '{print $2 " " $1}' | column -t | sort -u > subdomains-fierce

     cat subdomains-dnsrecon subdomains-fierce | egrep -v '(.nat.|1.1.1.1|6.9.6.9|127.0.0.1)' | column -t | tr '[A-Z]' '[a-z]' | sort -u | awk '$2 !~ /[a-z]/' > subdomains

     if [ -e $home/data/$domain/data/subdomains.htm ]; then
          cat $home/data/$domain/data/subdomains.htm subdomains | grep -v "<" | grep -v "$domain\." | column -t | sort -u > subdomains-combined
          echo '<pre style="font-size:14px;">' > $home/data/$domain/data/subdomains.htm
          cat subdomains-combined >> $home/data/$domain/data/subdomains.htm
          echo "</pre>" >> $home/data/$domain/data/subdomains.htm
     fi

     awk '{print $3}' records > tmp
     awk '{print $2}' subdomains-dnsrecon subdomains-fierce >> tmp
     grep -E '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}' tmp | egrep -v '(-|=|:|1.1.1.1|6.9.6.9|127.0.0.1)' | $sip > hosts

     echo
     echo "Loadbalancing             (6/$total)"
     lbd $domain > tmp 2>/dev/null
     # Remove first 5 lines & clean up
     sed '1,5d' tmp | sed 's/DNS-Loadbalancing: NOT FOUND/DNS-Loadbalancing:\nNOT FOUND\n/g' | sed 's/\[Date\]: /\[Date\]:\n/g' | sed 's/\[Diff\]: /\[Diff\]:\n/g' > tmp2
     # Replace the 10th comma with a new line & remove leading whitespace from each line
     sed 's/\([^,]*,\)\{9\}[^,]*,/&\n/g' tmp2 | sed 's/^[ \t]*//' | sed 's/, NOT/\nNOT/g' | grep -v 'NOT use' > loadbalancing

     echo
     echo "Web Application Firewall  (7/$total)"
     wafw00f -a http://www.$domain > tmp
     cat tmp | egrep -v '(By Sandro|Checking http://www.|Generic Detection|requests|WAFW00F)' > tmp2
     sed "s/ http:\/\/www.$domain//g" tmp2 | egrep -v "(\_|\^|\||<|')" | sed '1,4d' > waf

     echo
     echo "Traceroute"
     echo "     UDP                  (8/$total)"
     echo "UDP" > tmp
     traceroute $domain | awk -F" " '{print $1,$2,$3}' >> tmp
     echo >> tmp
     echo "ICMP ECHO" >> tmp
     echo "     ICMP ECHO            (9/$total)"
     traceroute -I $domain | awk -F" " '{print $1,$2,$3}' >> tmp
     echo >> tmp
     echo "TCP SYN" >> tmp
     echo "     TCP SYN              (10/$total)"
     traceroute -T $domain | awk -F" " '{print $1,$2,$3}' >> tmp
     grep -v 'traceroute' tmp > tmp2
     # Remove blank lines from end of file
     awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp2 > ztraceroute

     echo
     echo "Whatweb                   (11/$total)"
     grep -v '<' $home/data/$domain/data/subdomains.htm | awk '{print $1}' > tmp
     whatweb -i tmp --color=never --no-errors -t 255 > tmp2 2>/dev/null
     # Find lines that start with http, and insert a line after
     sort tmp2 | sed '/^http/a\ ' > tmp3
     # Cleanup
     sed 's/,/\n/g' tmp3 | sed 's/^[ \t]*//' | sed 's/\(\[[0-9][0-9][0-9]\]\)/\n\1/g; s/http:\/\///g' | grep -v 'Country' > whatweb

     grep '@' whatweb | sed 's/Email//g; s/\[//g; s/\]//g' > tmp
     # Change to lower case
     cat tmp | tr '[A-Z]' '[a-z]' > emails2

     cat emails1 emails2 | grep "@$domain" | grep -v 'hosting' | cut -d ' ' -f2 | sort -u > emails

     # If this file is empty, delete it
     if [ ! -s emails ]; then rm emails; fi
     if [ ! -s hosts ]; then rm hosts; fi
     if [ ! -s records ]; then rm records; fi
     if [ ! -s subdomains ]; then rm subdomains; fi

     echo
     echo "recon-ng                  (12/$total)"
     cp $discover/resource/recon-ng-active.rc $discover/
     sed -i "s/xxx/$companyurl/g" $discover/recon-ng-active.rc
     sed -i 's/%26/\&/g;s/%20/ /g;s/%2C/\,/g' $discover/recon-ng-active.rc
     sed -i "s/yyy/$domain/g" $discover/recon-ng-active.rc
     recon-ng --no-check -r $discover/recon-ng-active.rc

     grep "$domain" /tmp/subdomains | grep -v '>' | awk '{print $2,$4}' | column -t > sub-recon

     ##############################################################

     echo > zreport
     echo >> zreport

     echo "Summary" >> zreport
     echo $short >> zreport

     echo > tmp

     if [ -e emails ]; then
          emailcount=$(wc -l emails | cut -d ' ' -f1)
          echo "Emails        $emailcount" >> zreport
          echo "Emails ($emailcount)" >> tmp
          echo $short >> tmp
          cat emails >> tmp
          echo >> tmp
     fi

     if [ -e hosts ]; then
          hostcount=$(wc -l hosts | cut -d ' ' -f1)
          echo "Hosts         $hostcount" >> zreport
          echo "Hosts ($hostcount)" >> tmp
          echo $short >> tmp
          cat hosts >> tmp
          echo >> tmp
     fi

     if [ -e records ]; then
          recordcount=$(wc -l records | cut -d ' ' -f1)
          echo "DNS Records   $recordcount" >> zreport
          echo "DNS Records ($recordcount)" >> tmp
          echo $long >> tmp
          cat records >> tmp
          echo >> tmp
     fi

     if [ -e subdomains ]; then
          subdomaincount=$(wc -l subdomains | cut -d ' ' -f1)
          echo "Subdomains    $subdomaincount" >> zreport
          echo "Subdomains ($subdomaincount)" >> tmp
          echo $long >> tmp
          cat subdomains >> tmp
          echo >> tmp
     fi

     cat tmp >> zreport

     echo "Loadbalancing" >> zreport
     echo $long >> zreport
     cat loadbalancing >> zreport

     echo "Web Application Firewall" >> zreport
     echo $long >> zreport
     cat waf >> zreport

     echo >> zreport
     echo "Traceroute" >> zreport
     echo $long >> zreport
     cat ztraceroute >> zreport

     echo >> zreport
     echo "Zone Transfer" >> zreport
     echo $long >> zreport
     cat zonetransfer >> zreport

     echo >> zreport
     echo "Whatweb" >> zreport
     echo $long >> zreport
     cat whatweb >> zreport

     cat loadbalancing >> $home/data/$domain/data/loadbalancing.htm; echo "</pre>" >> $home/data/$domain/data/loadbalancing.htm
     cat zreport >> $home/data/$domain/data/active-recon.htm; echo "</pre>" >> $home/data/$domain/data/active-recon.htm
     cat ztraceroute >> $home/data/$domain/data/traceroute.htm; echo "</pre>" >> $home/data/$domain/data/traceroute.htm
     cat waf >> $home/data/$domain/data/waf.htm; echo "</pre>" >> $home/data/$domain/data/waf.htm
     cat whatweb >> $home/data/$domain/data/whatweb.htm; echo "</pre>" >> $home/data/$domain/data/whatweb.htm
     cat zonetransfer >> $home/data/$domain/data/zonetransfer.htm; echo "</pre>" >> $home/data/$domain/data/zonetransfer.htm

     if [[ -e $home/data/$domain/data/emails.htm && -e emails ]]; then
          cat $home/data/$domain/data/emails.htm emails | grep -v '<' | sort -u > tmp
          echo '<pre style="font-size:14px;">' > $home/data/$domain/data/emails.htm
          cat tmp >> $home/data/$domain/data/emails.htm; echo "</pre>" >> $home/data/$domain/data/emails.htm
     fi

     cat hosts $home/data/$domain/data/hosts.htm | grep -v '<' | $sip > tmp
     echo '<pre style="font-size:14px;">' > $home/data/$domain/data/hosts.htm
     cat tmp >> $home/data/$domain/data/hosts.htm; echo "</pre>" >> $home/data/$domain/data/hosts.htm

     mv recon-ng-active.rc $home/data/$domain/ 2>/dev/null
     rm emails* hosts loadbalancing records sub* tmp* waf whatweb z* 2>/dev/null

     echo
     echo $medium
     echo
     echo "***Scan complete.***"
     exit
}
f_domain