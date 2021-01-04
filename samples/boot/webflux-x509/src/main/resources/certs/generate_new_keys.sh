#!/bin/bash

#
# Copyright 2002-2021 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

KEYSTORE=${KEYSTORE:-"server.p12"}
PASSWORD=${PASSWORD:-"password"}
KEYSIZE=${KEYSIZE:-2048}
VALIDITY=${VALIDITY:-10000}

check() {
  if [ ! -f "$KEYSTORE" ]; then
    return 1
  fi

  currentdate=$(date +%s)
  for alias in $(keytool -list -v -keystore "$KEYSTORE" -storepass "$PASSWORD" | grep 'Alias name:' | perl -ne 'if(/name: (.*?)\n/) { print "$1\n"; }')
  do
    until=$(keytool -list -v -keystore "$KEYSTORE" -storepass "$PASSWORD" -alias "$alias" | grep 'Valid from' | head -1 | perl -ne 'if(/until: (.*?)\n/) { print "$1\n"; }')
    untilseconds=$(date -d "$until" +%s)
    if [ "$untilseconds" -le "$currentdate" ]; then
      return 1
    fi
  done
  return 0
}

renew() {
  # Thank you to granella for https://gist.github.com/granella/01ba0944865d99227cf080e97f4b3cb6

  rm *.p12 2> /dev/null
  rm *.pem 2> /dev/null

  # generate private keys (for root and ca)

  keytool -genkeypair -alias root -dname "cn=Local Network - Development" -validity "$VALIDITY" \
    -keyalg RSA -keysize "$KEYSIZE" -ext bc:c -keystore root.p12 -storetype PKCS12 \
    -keypass "$PASSWORD" -storepass "$PASSWORD"
  keytool -genkeypair -alias devca -dname "cn=Local Network - Development" -validity "$VALIDITY" \
    -keyalg RSA -keysize "$KEYSIZE" -ext bc:c -keystore ca.p12 -storetype PKCS12 \
    -keypass "$PASSWORD" -storepass "$PASSWORD"

  # generate root certificate

  keytool -exportcert -rfc -keystore root.p12 -alias root -storepass "$PASSWORD" > root.pem

  # generate a certificate for ca signed by root (root -> ca)

  keytool -keystore ca.p12 -storepass "$PASSWORD" -certreq -alias devca \
  | keytool -keystore root.p12 -storepass "$PASSWORD" -gencert -validity "$VALIDITY" \
    -alias root -ext bc=0 -ext san=dns:ca -rfc > ca.pem

  # import ca cert chain into ca.p12

  keytool -keystore ca.p12 -storepass "$PASSWORD" -importcert -trustcacerts -noprompt -alias root -file root.pem
  keytool -keystore ca.p12 -storepass "$PASSWORD" -importcert -alias devca -file ca.pem

  # generate private keys (for server)

  keytool -genkeypair -alias client -dname cn=client -validity "$VALIDITY" \
    -keyalg RSA -keysize "$KEYSIZE" -keystore "$KEYSTORE" -storetype PKCS12 \
    -keypass "$PASSWORD" -storepass "$PASSWORD"

  # generate a certificate for server signed by ca (root -> ca -> server)

  keytool -keystore "$KEYSTORE" -storepass "$PASSWORD" -certreq -alias client \
  | keytool -keystore ca.p12 -storepass "$PASSWORD" -gencert -validity "$VALIDITY" \
    -alias devca -ext ku:c=dig,keyEnc -ext "san=dns:localhost,ip:127.0.0.1" -ext eku=sa,ca -rfc > server.pem

  # import server cert chain into "$KEYSTORE"

  keytool -keystore "$KEYSTORE" -storepass "$PASSWORD" -importcert -trustcacerts -noprompt -alias root -file root.pem
  keytool -keystore "$KEYSTORE" -storepass "$PASSWORD" -importcert -alias devca -file ca.pem
  keytool -keystore "$KEYSTORE" -storepass "$PASSWORD" -importcert -alias client -file server.pem

  rm root.p12 ca.p12 2> /dev/null
  rm *.pem 2> /dev/null
}

if ! check; then renew; fi
