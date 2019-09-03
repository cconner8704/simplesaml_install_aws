- This installs SimpleSAMLPHP configured for nameid as a user source(TODO: Fix attributes)  
- You can specify the NameID format, persistent is only working one right now(TODO: Fix transient)  
- You can specify a base userid and number of users.  IE, ctest1...ctest10  
   
Example run:  
  
ssh -l root <samlhost>
yum -y install git  
git clone https://github.com/cmconner156/simplesaml_install_aws
/bin/bash ./simplesaml_install_config.sh --usercount 10 --userbase ctest --usersource nameid \  
                                         --nameformat persistent --newsaml  
  
  
usage: ./simplesaml_install_config.sh [options]  
  
Install and configure SimpleSAMLPHP.  MUST RUN ON SERVER THAT WILL BE SAML SERVER  
  
OPTIONS  
   -c|--usercount          Number of users to add to SAML config: 1  
   -u|--userbase           Base string to prepend to usernames in SAML config: user  
   -t|--timeout            How long to wait for SAML to startup
   -z|--workdir            Temp directory to store files: /tmp/simplesaml_install_config  
   -r|--newsaml            Clear out existing SAML and reinstall  
   -s|--usersource         Source for username in SAML, either nameid or attributes: nameid  
   -n|--nameformat         Nameid format, options, transient, persistent, unspecified2, unspecified1: persistent  
   -v|--verbose            Verbose logging  
   -?|--help               Show this message.  

- Quick start command:

./simplesaml_install_config.sh --newsaml

Troubleshooting:  

- Logs are here:  

/var/log/simplesamlphp.log  
/var/log/httpd/ssl_error_log  

