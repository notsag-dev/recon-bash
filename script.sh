# Get subdomains, web hosts and paths
echo 'Getting subs with assetfinder and amass'
(cat domains_scope.txt | assetfinder --subs-only > assetfinder_domains.txt) &

(cat domains_scope.txt | xargs -n1 -I{} /bin/bash -c "amass enum -d {}" >> amass_domains_to_clean.txt) &

wait

cat amass_domains_to_clean.txt | grep -v 'Querying\|Average' | sed -n '/^$/q;p' | sort -u >> amass_domains.txt
cat assetfinder_domains.txt amass_domains.txt | sort -u > domains_found.txt

echo 'HTTProbe and waybackurls'
cat domains_found.txt | httprobe > hosts.txt
cat domains_found.txt | waybackurls > waybackurls-to-clean.txt

# Process paths
cat waybackurls-to-clean.txt | grep -v '^$' > waybackurls.txt
cat waybackurls.txt | unfurl paths > waybackurls-paths.txt
sort -u waybackurls-paths.txt > waybackurls-paths-uniq.txt
mv waybackurls-paths-uniq.txt waybackurls-paths.txt

# Get web contents and extract extra information from them
echo 'Meg'
mkdir http
meg / hosts.txt http/
cd http
gf urls > ../gf-urls-to-clean.txt
cat ../gf-urls-to-clean.txt | grep -v "https://github.com/tomnomnom/meg)" > ../gf-urls.txt
gf base64 | awk -F'[=%]' '{print $2}' > ../gf-base64.txt
cd ..

# Create urls file
cat waybackurls.txt gf-urls.txt > urls.txt

echo 'Screenshots'
(cat hosts.txt | aquatone) &

# Bruteforcing paths
echo 'Fuzzing'
(cat hosts.txt | xargs -n1 -I{} /bin/bash -c "(echo 'HOST' {} && ffuf -u {}/FUZZ -w /Users/gastongimenez/repositories/SecLists/Discovery/Web-Content/common.txt -s -recursive) >> fuzz-paths.txt") &

wait
