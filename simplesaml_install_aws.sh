#!/bin/bash

#parse command line arguments
parse_arguments()
{
  # Test that we're using compatible getopt version.
  getopt -T > /dev/null
  if [[ $? -ne 4 ]]; then
    message "Incompatible getopt version."
    exit 1
  fi

  # Parse short and long option parameters.
  USERS=1
  NEW_SAML_INSTALL=
  WORK_DIR=/tmp/$(basename ${0%.*})
  USER_BASE=user
  USERNAME_SOURCE="nameid"
  NAMEID_FORMAT="persistent"
  TIMEOUT=120

  GETOPT=`getopt -n $0 -o t:,z:,c:,u:,r,s:,n:,v,d,? \
      -l timeout:,workdir:,usercount:,userbase:,newsaml,usersource:,nameformat:,verbose,trace,help \
      -- "$@"`
  eval set -- "$GETOPT"
  while true;
  do
    case "$1" in
    -t|--timeout)
      TIMEOUT=$2
      shift 2
      ;;
    -z|--workdir)
      WORK_DIR=$2
      shift 2
      ;;
    -c|--usercount)
      USERS=$2
      shift 2
      ;;
    -u|--userbase)
      USER_BASE=$2
      shift 2
      ;;
    -r|--newsaml)
      NEW_SAML_INSTALL=1
      shift
      ;;
    -s|--usersource)
      USERNAME_SOURCE=$2
      shift 2
      ;;
    -n|--nameformat)
      NAMEID_FORMAT=$2
      shift 2
      ;;
    -v|--verbose)
      VERBOSE=1
      shift
      ;;
    -d|--trace)
      TRACE=1
      shift
      ;;
    -\?|--help)
      usage
      exit 1
      ;;
    --)
      shift
      break
      ;;
    *)
      usage
      exit 1
      ;;
    esac
  done
  #
}

usage()
{
cat << EOF
usage: $0 [options]

Install and configure SimpleSAMLPHP on your cluster.  MUST RUN ON SERVER THAT WILL BE SAML SERVER

OPTIONS
   -c|--usercount          Number of users to add to SAML config: 1
   -u|--userbase           Base string to prepend to usernames in SAML config: user
   -t|--timeout            How long to wait for SAML to startup
   -z|--workdir            Temp directory to store files: /tmp/simplesaml_install_config
   -r|--newsaml            Clear out existing SAML and reinstall
   -s|--usersource         Source for username in SAML, either nameid or attributes: nameid
   -n|--nameformat         Nameid format, options, transient, persistent, unspecified2, unspecified1: persistent
   -v|--verbose            Verbose logging
   -t|--trace	           Trace logging
   -?|--help               Show this message.
EOF
}


main()
{



  parse_arguments "$@"

  if [[ ! -z ${TRACE} ]]
  then
    set -x
  fi

  SED=$(which sed)
  SCRIPT_DIR="$( cd -P "$( dirname "$0" )" && pwd )"
  IDP=$(curl -s http://169.254.169.254/latest/meta-data/public-hostname)
  SIMPLE_SAML=/opt/simplesamlphp
  SAML_CONFIG=${SIMPLE_SAML}/config/config.php
  SAML_LOG=/var/log/simplesamlphp.log
  SAML_DATA=${SIMPLE_SAML}/data
  SAML20_IDP_HOSTED=${SIMPLE_SAML}/metadata/saml20-idp-hosted.php
  SAML20_SP_HOSTED=${SIMPLE_SAML}/metadata/saml20-sp-remote.php
  SAML_AUTHSOURCES=${SIMPLE_SAML}/config/authsources.php
  SAML_ADMIN=admin
  SAML_ADMIN_PASS=admin
  TMP_SAML=/tmp/tmpsaml
  CERT_FILE=${SIMPLE_SAML}/cert/idp.pem
  KEY_FILE=${SIMPLE_SAML}/cert/idp.key
  IDP_METADATA=${TMP_SAML}/idp-metadata.xml
  CLIENT_METADATA=${TMP_SAML}/client-metadata.xml
  COOKIE_JAR=${WORK_DIR}/cookie.jar
  CURL=$(which curl)
  if [[ -z ${CURL} ]]
  then
    message "curl must be installed and which curl must return path"
    exit 1
  fi
  METADATA_CURL="${CURL} -s -k https://${IDP}/simplesaml/saml2/idp/metadata.php"
  HTTPD_CONF=/etc/httpd/conf.d

  #IMPORTANT ADD 443 CHECK

  if [[ ! -z ${NEW_SAML_INSTALL} ]]
  then
    message "Clearing out existing SAML for new install"
    rm -Rf ${TMP_SAML}
    rm -Rf ${SIMPLE_SAML}
    rm -Rf /opt/simplesaml*
    rm -f ${SAML_LOG}
    rm -f ${HTTPD_CONF}/simple*
    rm -f /etc/rsyslog.d/simple*
  fi

  if [[ ! ${USER} =~ .*root.* ]]
  then
    message "Script must be run as root: exiting"
    exit 1
  fi

  if [[ ! -d ${TMP_SAML} ]]
  then
    mkdir -p ${TMP_SAML}
  fi

  if [[ ! -d ${WORK_DIR} ]]
  then
    mkdir -p ${WORK_DIR}
  fi

  integer_re='^[0-9]+$'
  if ! [[ ${USERS} =~ ${integer_re} ]]
  then
    message "-u <users> must be a number"
    usage
    exit 1
  fi

  if [[ ! ${USERNAME_SOURCE} =~ "attributes" ]]
  then
    message "Username source was not 'attributes', using 'nameid'.  Only 'attributes' or 'nameid' are allowed"
    message "If you do not want 'nameid', then use '--usersource attributes'"
    USERNAME_SOURCE="nameid"
  fi

  case "${NAMEID_FORMAT}" in
    transient)
      NAMEID_FORMAT="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
      ;;
    persistent)
      NAMEID_FORMAT="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
      ;;
    unspecified1)
      NAMEID_FORMAT="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
      ;;
    unspecified2)
      NAMEID_FORMAT="urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"
      ;;
    *)
      message "Only options for --nameformat are transient, persistent, unspecified1, unspecified2, defaulting to transient"
      NAMEID_FORMAT="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
      ;;
  esac

  IDP_TEST=$(${METADATA_CURL} | grep entityID)
  if [[ -z ${IDP_TEST} ]]
  then

    message "SimpleSAML not already installed, installing now"

     yum -y install httpd mod_ssl php php-mcrypt php-xml php-pdo php-mbstring

    if [[ -d ${HTTPD_CONF} ]]
    then

cat >> ${HTTPD_CONF}/simplesaml.conf << EOF
Alias /simplesaml ${SIMPLE_SAML}/www

<Directory ${SIMPLE_SAML}/www>
  AllowOverride none
  Require all granted
</Directory>
EOF

    message "Installed required packages for SimpleSAML and configured HTTPD"
    else
      message "HTTPD install failed"
      exit 1
    fi

    cd /opt && wget -O simplesaml.tar.gz https://simplesamlphp.org/download?latest
    tar zxf simplesaml.tar.gz
    ln -s $(ls -d /opt/simplesamlphp*) ${SIMPLE_SAML}

    if [[ ! -f ${SAML_CONFIG} ]]
    then
      message "SimpleSAML download and extract failed"
      exit 1
    else
      message "SimpleSAML downloaded and extracted"
    fi


    # Edit config.php
    export SALT=`tr -c -d '0123456789abcdefghijklmnopqrstuvwxyz' </dev/urandom | dd bs=32 count=1 2>/dev/null;echo`
    ${SED} -i "s/defaultsecretsalt/$SALT/" ${SAML_CONFIG}
    ${SED} -i "s/'auth.adminpassword' => '123'/'auth.adminpassword' => 'admin'/" ${SAML_CONFIG}
#    ${SED} -i "s/na@example.org/no-user@example.org/" ${SAML_CONFIG}
    ${SED} -i "s/'timezone' => null/'timezone' => 'America\/Los_Angeles'/" ${SAML_CONFIG}
    ${SED} -i "s/'enable.saml20-idp' => false/'enable.saml20-idp' => true/" ${SAML_CONFIG}
    ${SED} -i "s^'store.type'.*^'store_type' => 'sql',^g" ${SAML_CONFIG}
    ${SED} -i "s^'store.sql.dsn'.*^'store.sql.dsn' => 'sqlite:/opt/simplesamlphp/data/sqlitedatabase.sq3',^g" ${SAML_CONFIG}
    ${SED} -i "s^'logging.level'.*^'logging.level' => SimpleSAML\\\Logger::DEBUG,^g" ${SAML_CONFIG}
    message "Updated ${SAML_CONFIG}"

    cat >> /etc/rsyslog.d/simplesaml.conf << EOF
# SimpleSAMLphp logging
local5.*                        ${SAML_LOG}
# Notice level is reserved for statistics only...
# local5.=notice                  /var/log/simplesamlphp.stat
EOF

    touch ${SAML_LOG}
    chown apache.apache ${SAML_LOG}
    systemctl restart rsyslog
    message "SimpleSAML configured to log to ${SAML_LOG}"

    mkdir -p ${SAML_DATA}
    chown apache.apache ${SAML_DATA}

    # Create a custom authentication module (https://simplesamlphp.org/docs/stable/simplesamlphp-customauth)
    mkdir -p ${SIMPLE_SAML}/modules/customauth
    cp ${SIMPLE_SAML}/modules/core/default-enable ${SIMPLE_SAML}/modules/customauth/

    # Create authentication source
    CUSTOM_AUTH_DIR=${SIMPLE_SAML}/modules/customauth/lib/Auth/Source
    CUSTOM_AUTH_FILE=${CUSTOM_AUTH_DIR}/CustomAuth.php
    mkdir -p ${CUSTOM_AUTH_DIR}
    cat > ${CUSTOM_AUTH_FILE} <<EOF
<?php
class sspmod_customauth_Auth_Source_CustomAuth extends sspmod_core_Auth_UserPassBase {
    private \$groupname;
    protected function login(\$username, \$password) {
EOF


echo "        if (\$username == 'admin' AND \$password == \$username) {" >> ${CUSTOM_AUTH_FILE}
echo "            \$groupname = 'admin';" >> ${CUSTOM_AUTH_FILE}
echo "            \$email = 'admin@example.com';" >> ${CUSTOM_AUTH_FILE}

for ((USERID=1; USERID<=${USERS}; USERID++))
do
  echo "        } elseif (\$username == '${USER_BASE}${USERID}' AND \$password == \$username) {" >> ${CUSTOM_AUTH_FILE}
  echo "            \$groupname = 'group${USERID}';" >> ${CUSTOM_AUTH_FILE}
  echo "            \$email = 'user${USERID}@example.com';" >> ${CUSTOM_AUTH_FILE}
done

    cat >> ${CUSTOM_AUTH_FILE} <<EOF
        } else {
            throw new SimpleSAML_Error_Error('WRONGUSERPASS');
        }
        return array(
            'uid' => array(\$username),
            'displayName' => array(\$username),
            'eduPersonAffiliation' => array('member', \$username),
            'organizationalUnitName' => array(\$groupname),
            'mail' => array($email),
            'email' => array($email),
        );
    }
}
EOF

    message "Created custom authentication source"

    # Insert auth source into authsources.php (lines 4,5,6)
    cat > ${SAML_AUTHSOURCES} << EOF
<?php

\$config = array(
    'customauthinstance' => array(
        'customauth:CustomAuth',
    ),

    // This is a authentication source which handles admin authentication.
    'admin' => array(
        // The default is to use core:AdminPassword, but it can be replaced with
        // any authentication source.
        'core:AdminPassword',
    ),

);
EOF

    message "Created ${SIMPLE_SAML}/config/authsources.php"

    # Create saml20-idp-hosted.php
    cat > ${SAML20_IDP_HOSTED} << EOF
<?php
/**
 * SAML 2.0 IdP configuration for SimpleSAMLphp.
 * See: https://simplesamlphp.org/docs/stable/simplesamlphp-reference-idp-hosted
 */

\$metadata['__DYNAMIC:1__'] = array(
	'host' => '${IDP}',
	'privatekey' => 'idp.key',
	'certificate' => 'idp.pem',
	'auth' => 'customauthinstance',
	'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
	 'NameIDFormat' => '${NAMEID_FORMAT}',
     // refer to https://simplesamlphp.org/docs/stable/saml:nameid
     'authproc' => array(
       3 => array(
            'class' => 'saml:AttributeNameID',
            'attribute' => 'uid',
            'Format' => '${NAMEID_FORMAT}',
       ),
       100 => array('class' => 'core:AttributeMap', 'name2oid'),
     ),

);
EOF

    message "Created ${SIMPLE_SAML}/metadata/saml20-idp-hosted.php"


    # Create cert files
    message "Creating SAML Certs"
    SSL_SUBJECT="/C=US/ST=CA/L=Bay Area/O=Support/OU=Support SAML/CN=${IDP}"
    openssl req -newkey rsa:2048 -new -x509 -days 365 -nodes -out ${CERT_FILE} -keyout ${KEY_FILE} -subj "${SSL_SUBJECT}"
    message "Created cert files"

    #Start SimpleSAML by starting HTTPD
    systemctl restart httpd

    IDP_TEST=
    SLEEP_COUNT=0
    while [[ -z ${IDP_TEST} ]]
    do
      if [[ ${SLEEP_COUNT} -gt ${TIMEOUT} ]]
      then
        break
      fi
      SLEEP_COUNT=$(expr ${SLEEP_COUNT} + 1)
      sleep 1
      IDP_TEST=$(${METADATA_CURL} | grep entityID)
    done
    if [[ -z ${IDP_TEST} ]]
    then
      message "Something went wrong, unable to get metadata xml"
      exit 1
    fi

    ${METADATA_CURL} --output ${IDP_METADATA}
    message "Got IDP metadata: ${IDP_METADATA}"

  else
    message "SimpleSAML already installed, skipping"
  fi

##############THIS IS TEST STUFF##############

#  SIMPLE_SAML_CURL="${CURL} -k -b @${COOKIE_JAR} -c ${COOKIE_JAR} "
#  SIMPLE_SAML_URL="https://${IDP}/simplesaml"
#  CONVERTED_METADATA="${WORK_DIR}/converted_metadata.html"

#  AUTH_URL=$(${SIMPLE_SAML_CURL} "${SIMPLE_SAML_URL}/module.php/core/login-admin.php?ReturnTo=$(urlencode ${SIMPLE_SAML_URL})%2Fmodule.php%2Fcore%2Ffrontpage_federation.php" | grep "href=" | awk -Fhref= '{print $2}' | awk -F\> '{print $1}')

#  AUTH_STATE_ID=$(echo ${AUTH_URL} | awk -FAuthState= '{print $2}' | awk -F\% '{print $1}')

#  AUTH_STATE="${AUTH_STATE_ID}:${SIMPLE_SAML_URL}/module.php/core/as_login.php?AuthId=${SAML_ADMIN}&ReturnTo=${SIMPLE_SAML_URL}/module.php/core/login-admin.php?ReturnTo=${SIMPLE_SAML_URL}/module.php/core/frontpage_federation.php"

#  ${SIMPLE_SAML_CURL} -F password="${SAML_ADMIN_PASS}" -F AuthState="${AUTH_STATE}" -X POST "${SIMPLE_SAML_URL}/module.php/core/loginuserpass.php?"

#  ${SIMPLE_SAML_CURL} -F xmlfile=@${CLIENT_METADATA} -X POST "${SIMPLE_SAML_URL}/admin/metadata-converter.php?" --output ${CONVERTED_METADATA}

#  echo "" >> ${SAML20_SP_HOSTED}
#  sed -n '/id="metadata1">/,$p' ${CONVERTED_METADATA} | sed '/^);/q' | sed 's/.*<pre id="metadata1">//g' >> ${SAML20_SP_HOSTED}
#  sed -i "s/=&gt;/=>/g" ${SAML20_SP_HOSTED}

  #Restart to pickup the changes
#  systemctl restart httpd

#  IDP_TEST=
#  SLEEP_COUNT=0
#  while [[ -z ${IDP_TEST} ]]
#  do
#    if [[ ${SLEEP_COUNT} -gt ${TIMEOUT} ]]
#    then
#      break
#    fi
#    SLEEP_COUNT=$(expr ${SLEEP_COUNT} + 1)
#    sleep 1
#    IDP_TEST=$(${METADATA_CURL} | grep entityID)
#  done
#  if [[ -z ${IDP_TEST} ]]
#  then
#    echo "Something went wrong, SimpleSaml did not come back up"
#    exit 1
#  fi

}

test_site_ssl() {

  TEST_HOST=$1
  TEST_PORT=$2
  TEST_URL=$3
  TEST_CONNECT=${TEST_HOST}:${TEST_PORT}${TEST_URL}
  message "Testing ${TEST_CONNECT}"
  cat < /dev/null > /dev/tcp/${TEST_HOST}/${TEST_PORT} 2>/dev/null
  if [[ $? -gt 0 ]]
  then
    message "Nothing listening at ${TEST_CONNECT}"
    exit 1
  else
    wget --no-check-certificate --spider https://${TEST_CONNECT} 2>/dev/null
    if [[ $? -eq 0 ]]
    then
      echo "https"
    else
      echo "http"
    fi
  fi
}

message()
{
  if [[ ! -z ${VERBOSE} ]]
  then
    echo "$1"
  elif [[ -z $2 ]]
  then
    echo "$1"
  fi
}

urlencode() {
    # urlencode <string>
    old_lc_collate=$LC_COLLATE
    LC_COLLATE=C

    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        case $c in
            [a-zA-Z0-9.~_-]) printf "$c" ;;
            *) printf '%%%02X' "'$c" ;;
        esac
    done

    LC_COLLATE=$old_lc_collate
}

urldecode() {
    # urldecode <string>

    local url_encoded="${1//+/ }"
    printf '%b' "${url_encoded//%/\\x}"
}

main "$@"
