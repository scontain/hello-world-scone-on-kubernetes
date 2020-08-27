#!/bin/bash
: '
Access to this file is granted under the SCONE COMMERCIAL LICENSE V1.0 

Any use of this product using this file requires a commercial license from scontain UG, www.scontain.com.

Permission is also granted  to use the Program for a reasonably limited period of time  (but no longer than 1 month) 
for the purpose of evaluating its usefulness for a particular purpose.

THERE IS NO WARRANTY FOR THIS PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING 
THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. 

THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, 
YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED ON IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY
MODIFY AND/OR REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, 
INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM INCLUDING BUT NOT LIMITED TO LOSS 
OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE 
WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

Copyright (C) 2017-2020 scontain.com
'

# set IMAGEREPO to a repo you are permitted to push to ...
export IMAGEREPO=${IMAGEREPO:-sconecuratedimages/kubernetes}

# modify if needed
export SCONE_CAS_ADDR=4-0-0.scone-cas.cf
export SCONE_CAS_IMAGE="sconecuratedimages/services:cas-scone4.0"
#export CAS_MRENCLAVE=`(docker pull $SCONE_CAS_IMAGE > /dev/null ; docker run -i --rm -e "SCONE_HASH=1" $SCONE_CAS_IMAGE cas) || echo 9a1553cd86fd3358fb4f5ac1c60eb8283185f6ae0e63de38f907dbaab7696794`  # compute MRENCLAVE for current CAS
export CAS_MRENCLAVE=460e24c965a94fd3718cb22472926c9517fb2912d2c8ca97ea26228e14d0bbdd
export BASE_IMAGE=sconecuratedimages/apps:python-3.7.3-alpine3.10
export NAMESPACE=hello-scone-$RANDOM
set -e

# print the right color for each level
#
# Arguments:
# 1:  level

function msg_color {
    priority=$1
    if [[ $priority == "fatal" ]] ; then
        echo -e "\033[31m"
    elif [[ $priority == "error" ]] ; then
        echo -e "\033[34m"
    elif [[ $priority == "warning" ]] ; then
        echo -e "\033[35m"
    elif [[ $priority == "info" ]] ; then
        echo -e "\033[36m"
    elif [[ $priority == "debug" ]] ; then
        echo -e "\033[37m"
    elif [[ $priority == "default" ]] ; then
        echo -e "\033[00m"
    else
        echo -e "\033[32m";
    fi
}

function no_error_message {
    exit $? 
}

FORWARD1=""
FORWARD2=""
FORWARD3=""

function issue_error_exit_message {
    errcode=$?
    trap no_error_message EXIT
    if [[ $errcode != 0 ]] ; then
        msg_color "fatal"
        echo -e "ERROR: run-hello-world.sh failed (Line: ${BASH_LINENO[0]})"
        echo -e "MITIGATION:" $mitigation
        msg_color "default"
    else
        msg_color "OK"
        echo "OK"
        msg_color "default"
    fi
    # cleanup
    echo "Cleaning up..."
    kubectl delete namespace $NAMESPACE
    if [[ "$FORWARD1"x != "x" ]] ; then
        kill -9 $FORWARD1 || echo "$FORWARD1 already killed"
    fi
    if [[ "$FORWARD2"x != "x" ]] ; then
        kill -9 $FORWARD2 || echo "$FORWARD2 already killed"
    fi
    if [[ "$FORWARD3"x != "x" ]] ; then
        kill -9 $FORWARD3 || echo "$FORWARD3 already killed"
    fi
    if [[ "$FORWARD4"x != "x" ]] ; then
        kill -9 $FORWARD4 || echo "$FORWARD4 already killed"
    fi
    exit $errcode
}

trap issue_error_exit_message EXIT

# use a separate namespace
echo "Create namespace $NAMESPACE"
mitigation="Delete namespace by executing 'kubectl delete namespace $NAMESPACE'"
kubectl create namespace $NAMESPACE

# Workspace
mitigation="Please look at error log."
cd $(mktemp -d)
echo "Workspace: $PWD"

# CAS


echo "Generate key pair for communicating with CAS (=$SCONE_CAS_ADDR)"
mkdir -p conf
if [[ ! -f conf/client.crt || ! -f conf/client-key.key  ]] ; then
    openssl req -x509 -newkey rsa:4096 -out conf/client.crt -keyout conf/client-key.key  -days 31 -nodes -sha256 -subj "/C=US/ST=Dresden/L=Saxony/O=Scontain/OU=Org/CN=www.scontain.com" -reqexts SAN -extensions SAN -config <(cat /etc/ssl/openssl.cnf \
<(printf '[SAN]\nsubjectAltName=DNS:www.scontain.com'))
fi

## Hello World Program

echo "Creating Hello World program"

mkdir -p app
cat > app/server.py << EOF
from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
import os


class HTTPHelloWorldHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """say "Hello World!" and the value of \`GREETING\` env. variable."""
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Hello World!\n\$GREETING is: %s\n' % (os.getenv('GREETING', 'no greeting :(').encode()))


httpd = HTTPServer(('0.0.0.0', 8080), HTTPHelloWorldHandler)


httpd.serve_forever()
EOF

echo "Creating Dockerfile"

cat > Dockerfile << EOF
FROM $BASE_IMAGE
EXPOSE 8080
COPY app /app
CMD [ "python3", "/app/server.py" ]
EOF

echo "Creating image"

export IMAGETAG1=hello-k8s-scone0.1
export IMAGE=$IMAGEREPO:$IMAGETAG1
docker build --pull . -t $IMAGE || echo "docker build of $IMAGE failed - try to get access to the SCONE community version. Continue with prebuilt images."

mitigation="Please define an image name '$IMAGE' that you are permitted to push"
docker push $IMAGE || echo "docker push of $IMAGE failed - assuming that the image is already there."

echo "Create Kubernetes manifests"

mitigation="check log above"
cat > app.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hello-world
spec:
  selector:
    matchLabels:
      run: hello-world
  replicas: 1
  template:
    metadata:
      labels:
        run: hello-world
    spec:
      containers:
      - name: hello-world
        image: $IMAGE
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
        env:
        - name: GREETING
          value: howdy!
        resources:
          limits:
            sgx.k8s.io/sgx: 1
---
apiVersion: v1
kind: Service
metadata:
  name: hello-world
  labels:
    run: hello-world
spec:
  ports:
  - port: 8080
    protocol: TCP
  selector:
    run: hello-world
EOF

echo "submit the manifests"
mitigation="check that your 'kubectl' is properly configured."
kubectl create -f app.yaml -n $NAMESPACE

echo "forward port to localhost - ensure we give service enough time to start up"

sleep 10
mitigation="check that sleep times are sufficiently long."
kubectl port-forward svc/hello-world 8080:8080 -n $NAMESPACE &
FORWARD1=$!
sleep 10

if ps -p $FORWARD1 > /dev/null
then
    echo "Tunnel seems to be up."
else
    wait $FORWARD1
    exit_status=$?
    echo "port-forward failed."
    exit $exit_status
fi

echo "Querying Service"

mitigation="check that sleep time for establishing tunnel is sufficiently long."
EXPECTED='Hello World!
$GREETING is: howdy!'
MSG=$(curl localhost:8080)
echo "Got message:$MSG"
mitigation="See error log above"

if [[ "$MSG" != "$EXPECTED" ]] ; then
    mitigation="Check that service actually runs."
    echo "Got wrong result: $MSG"
    echo "    and expected: $EXPECTED"
    exit 1
fi

echo "## Run with remote attestation"

cat > las.yaml << EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: local-attestation
  labels:
    k8s-app: local-attestation
spec:
  selector:
    matchLabels:
      k8s-app: local-attestation
  template:
    metadata:
      labels:
        k8s-app: local-attestation
    spec:
      hostNetwork: true
      containers:
        - name: local-attestation
          image: sconecuratedimages/kubernetes:las
          ports:
          - containerPort: 18766
            hostPort: 18766
          resources:
            limits:
              sgx.k8s.io/sgx: 1
EOF

kubectl create -f las.yaml -n $NAMESPACE

echo "Attest CAS"

mitigation="Update CAS_MRENCLAVE to the current MRENCLAVE"
docker run -e SCONE_MODE=SIM  -it --rm $BASE_IMAGE scone cas attest -G --only_for_testing-debug  $SCONE_CAS_ADDR $CAS_MRENCLAVE

echo "Determine MRENCLAVE on local host (assuming this host is trusted)"

mitigation="Check log above"
MRENCLAVE=`docker run -i --rm -e "SCONE_HASH=1" $IMAGE`

echo "MRENCLAVE=$MRENCLAVE"

echo "Create SCONE CAS Policy"
SESSION=hello-k8s-scone-$RANDOM-$RANDOM

cat > session.yaml << EOF
name: $SESSION
version: "0.2"

services:
   - name: application
     mrenclaves: [$MRENCLAVE]
     command: python3 /app/server.py
     pwd: /
     environment:
        GREETING: hello from SCONE!!!
EOF

response_file="$(mktemp)"
http_code="$(curl -k --cert conf/client.crt --key conf/client-key.key --data-binary @session.yaml -XPOST https://$SCONE_CAS_ADDR:8081/session -o ${response_file} -s -w '%{http_code}' || echo 100)" 

if test "$http_code" -ne 201; then
    echo "Session uploading failed!" 
    echo "CAS HTTP Response Code $http_code" 
    cat $response_file 
    echo "Session="
    cat session.yaml
    echo ""
    exit 1
else
    echo "Uploaded session $SESSION: Reply=$(cat $response_file)"
fi

echo "Starting Attested hello world"

cat > attested-app.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: attested-hello-world
spec:
  selector:
    matchLabels:
      run: attested-hello-world
  replicas: 1
  template:
    metadata:
      labels:
        run: attested-hello-world
    spec:
      containers:
      - name: attested-hello-world
        image: $IMAGE
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
        env:
        - name: SCONE_CAS_ADDR
          value: $SCONE_CAS_ADDR
        - name: SCONE_CONFIG_ID
          value: $SESSION/application
        - name: SCONE_LAS_ADDR
          value: 172.17.0.1:18766
        - name: SCONE_LOG
          value: "7"
        resources:
          limits:
            sgx.k8s.io/sgx: 1
---
apiVersion: v1
kind: Service
metadata:
  name: attested-hello-world
  labels:
    run: attested-hello-world
spec:
  ports:
  - port: 8080
    protocol: TCP
  selector:
    run: attested-hello-world
EOF

kubectl create -f attested-app.yaml -n $NAMESPACE

sleep 10
mitigation="check that sleep times are sufficiently long."

kubectl port-forward svc/attested-hello-world 8082:8080 -n $NAMESPACE &
FORWARD2=$!
sleep 10

if ps -p $FORWARD2 > /dev/null
then
    echo "Tunnel 8082 seems to be up."
else
    wait $FORWARD2
    exit_status=$?
    echo "port-forward2 failed."
    exit $exit_status
fi

echo "Querying Service"
# output the LOG
kubectl logs -n $NAMESPACE --max-log-requests=50 --selector=run=attested-hello-world

mitigation="check that sleep time for establishing tunnel is sufficiently long."
EXPECTED='Hello World!
$GREETING is: hello from SCONE!!!'
MSG=$(curl localhost:8082)
echo "Got message: $MSG"
mitigation="See error log above"

if [[ "$MSG" != "$EXPECTED" ]] ; then
    mitigation="Check that service actually runs."
    echo "Got wrong result: $MSG"
    echo "    and expected: $EXPECTED"
    exit 1
fi

echo "# TLS with certificates auto-generated by CAS"

cat > app/server-tls.py << EOF
from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
import os
import socket
import ssl


class HTTPHelloWorldHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """say "Hello World!" and the value of \`GREETING\` env. variable."""
        print("got request")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Hello World!\n\$GREETING is: %s\n' % (os.getenv('GREETING', 'no greeting :(').encode()))


httpd = HTTPServer(('0.0.0.0', 4443), HTTPHelloWorldHandler)

print("Server started")
httpd.socket = ssl.wrap_socket(httpd.socket,
                               keyfile="/app/key.pem",
                               certfile="/app/cert.pem",
                               server_side=True)

print("Listening on Port 4443")
httpd.serve_forever()
EOF

cat > Dockerfile << EOF
FROM $BASE_IMAGE
EXPOSE 4443
COPY app /app
CMD [ "python3" ]
EOF

export IMAGETAG2=hello-k8s-scone0.2
export IMAGE=$IMAGEREPO:$IMAGETAG2

echo "build image $IMAGE"
docker build --pull . -t $IMAGE || echo "docker build of $IMAGE failed - try to get access to the SCONE community version. Continue with prebuilt images."

# push might fail - which is ok since this image already exists
docker push $IMAGE || echo "docker push of $IMAGE failed - assuming that the image is already there."

# let's extra MRENCLAVE again (just in case..)
MRENCLAVE=$(docker run -i --rm -e "SCONE_HASH=1" $IMAGE)

SESSION=hello-k8s-scone-tls-certs-$RANDOM

cat > session-tls-certs.yaml << EOF
name: $SESSION
version: "0.2"

services:
   - name: application
     image_name: application_image
     mrenclaves: [$MRENCLAVE]
     command: python3 /app/server-tls.py
     pwd: /
     environment:
        GREETING: hello from SCONE with TLS and auto-generated certs!!!

images:
   - name: application_image
     injection_files:
       - path:  /app/cert.pem
         content: \$\$SCONE::SERVER_CERT.crt\$\$
       - path: /app/key.pem
         content: \$\$SCONE::SERVER_CERT.key\$\$

secrets:
   - name: SERVER_CERT
     kind: x509
EOF

http_code="$(curl -k --cert conf/client.crt --key conf/client-key.key --data-binary @session-tls-certs.yaml -XPOST https://$SCONE_CAS_ADDR:8081/session -o ${response_file} -s -w '%{http_code}' || echo 100)" 

if test "$http_code" -ne 201; then
    echo "Session uploading failed!" 
    echo "CAS HTTP Response Code $http_code" 
    cat $response_file 
    echo "Session="
    cat session.yaml
    echo ""
    exit 1
else
    echo "Uploaded session $SESSION: Reply=$(cat $response_file)"
fi


cat > attested-app-tls-certs.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: attested-hello-world-tls-certs
spec:
  selector:
    matchLabels:
      run: attested-hello-world-tls-certs
  replicas: 1
  template:
    metadata:
      labels:
        run: attested-hello-world-tls-certs
    spec:
      containers:
      - name: attested-hello-world-tls-certs
        image: $IMAGE
        imagePullPolicy: Always
        ports:
        - containerPort: 4443
        env:
        - name: SCONE_CAS_ADDR
          value: $SCONE_CAS_ADDR
        - name: SCONE_CONFIG_ID
          value: $SESSION/application
        - name: SCONE_LAS_ADDR
          value: "172.17.0.1"
        - name: SCONE_LOG
          value: "7"
        resources:
          limits:
            sgx.k8s.io/sgx: 1
---
apiVersion: v1
kind: Service
metadata:
  name: attested-hello-world-tls-certs
  labels:
    run: attested-hello-world-tls-certs
spec:
  ports:
  - port: 4443
    protocol: TCP
  selector:
    run: attested-hello-world-tls-certs
EOF

kubectl create -f attested-app-tls-certs.yaml -n $NAMESPACE

sleep 10
mitigation="check that sleep times are sufficiently long."
kubectl port-forward svc/attested-hello-world-tls-certs 8083:4443 -n $NAMESPACE &
FORWARD3=$!
sleep 10

if ps -p $FORWARD3 > /dev/null
then
    echo "Tunnel3 seems to be up."
else
    wait $FORWARD3
    exit_status=$?
    echo "port-forward failed."
    exit $exit_status
fi

echo "Logs"
kubectl logs -n $NAMESPACE --max-log-requests=50 --selector=run=attested-hello-world-tls-certs

mitigation="check that sleep time for establishing tunnel is sufficiently long."
EXPECTED='Hello World!
$GREETING is: hello from SCONE with TLS and auto-generated certs!!!'
MSG=$(curl -k https://localhost:8083)
echo "Got message: $MSG"
mitigation="See error log above"

if [[ "$MSG" != "$EXPECTED" ]] ; then
    mitigation="Check that service actually runs."
    echo "Got wrong result: $MSG"
    echo "    and expected: $EXPECTED"
    exit 1
fi

echo "Encrypted application code"


docker run -it -e SCONE_MODE=SIM --rm -v $PWD:/tutorial $BASE_IMAGE sh -c "cd /tutorial
  rm -rf app_image && mkdir -p app_image/app && \
  cd app_image  && \
  scone fspf create fspf.pb && \
  scone fspf addr fspf.pb / --not-protected --kernel /   && \
  scone fspf addr fspf.pb /app --encrypted --kernel /app  && \
  scone fspf addf fspf.pb /app /tutorial/app /tutorial/app_image/app  && \
  scone fspf encrypt fspf.pb > /tutorial/app/keytag
" || echo "encryption of Python code failed - try to get access to the SCONE community version. Continuing."

echo "app_image/app"
ls -l app_image/app

cat app_image/app/server-tls.py  || echo "file does not exits"


cat > Dockerfile << EOF
FROM $BASE_IMAGE
EXPOSE 4443
COPY app_image /
CMD [ "python3" ]
EOF


export IMAGETAG3=hello-k8s-scone0.3
export IMAGE3=$IMAGEREPO:$IMAGETAG3

echo "build image $IMAGE3"

docker build --pull . -t $IMAGE3  ||  echo "docker build of $IMAGE3 failed - try to get access to the SCONE community version. Continue with prebuilt images. "
docker push $IMAGE3 || echo "$(msg_color error) docker push of $IMAGE3 failed - continuing but running will eventually fail! Please change IMAGEREPO such that you are permitted to push too. $(msg_color default)"


export SCONE_FSPF_KEY=$(cat app/keytag | awk '{print $11}')
export SCONE_FSPF_TAG=$(cat app/keytag | awk '{print $9}')
export SCONE_FSPF=/fspf.pb

SESSION=hello-k8s-scone-tls-$RANDOM

cat > session-tls.yaml << EOF
name: $SESSION
version: "0.2"

services:
   - name: application
     image_name: application_image
     mrenclaves: [$MRENCLAVE]
     command: python3 /app/server-tls.py
     pwd: /
     environment:
        GREETING: hello from SCONE with encrypted source code and auto-generated certs!!!
     fspf_path: $SCONE_FSPF
     fspf_key: $SCONE_FSPF_KEY
     fspf_tag: $SCONE_FSPF_TAG

images:
   - name: application_image
     injection_files:
       - path:  /app/cert.pem
         content: \$\$SCONE::SERVER_CERT.crt\$\$
       - path: /app/key.pem
         content: \$\$SCONE::SERVER_CERT.key\$\$

secrets:
   - name: SERVER_CERT
     kind: x509
EOF

http_code="$(curl -k --cert conf/client.crt --key conf/client-key.key --data-binary @session-tls.yaml -XPOST https://$SCONE_CAS_ADDR:8081/session -o ${response_file} -s -w '%{http_code}' || echo 100)" 

if test "$http_code" -ne 201; then
    echo "Session uploading failed!" 
    echo "CAS HTTP Response Code $http_code" 
    cat $response_file 
    echo "Session="
    cat session.yaml
    echo ""
    exit 1
else
    echo "Uploaded session $SESSION: Reply=$(cat $response_file)"
fi


cat > attested-app-tls.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: attested-hello-world-tls
spec:
  selector:
    matchLabels:
      run: attested-hello-world-tls
  replicas: 1
  template:
    metadata:
      labels:
        run: attested-hello-world-tls
    spec:
      containers:
      - name: attested-hello-world-tls
        image: $IMAGE3
        imagePullPolicy: Always
        ports:
        - containerPort: 4443
        env:
        - name: SCONE_CAS_ADDR
          value: $SCONE_CAS_ADDR
        - name: SCONE_CONFIG_ID
          value: $SESSION/application
        - name: SCONE_LAS_ADDR
          value: 172.17.0.1
        - name: SCONE_LOG
          value: "7"
        resources:
          limits:
            sgx.k8s.io/sgx: 1
---
apiVersion: v1
kind: Service
metadata:
  name: attested-hello-world-tls
  labels:
    run: attested-hello-world-tls
spec:
  ports:
  - port: 4443
    protocol: TCP
  selector:
    run: attested-hello-world-tls
EOF

kubectl create -f attested-app-tls.yaml -n $NAMESPACE


sleep 10
mitigation="$(msg_color error) Where you able to push the image ($IMAGE)? If not, you need to change IMAGEREPO - you cannot run somebody else's encrypted image $(msg_color ok)"
kubectl port-forward svc/attested-hello-world-tls 8084:4443 -n $NAMESPACE &
FORWARD4=$!
sleep 10
kubectl logs -n $NAMESPACE --max-log-requests=50 --selector=run=attested-hello-world-tls

if ps -p $FORWARD4 > /dev/null
then
    echo "Tunnel4 seems to be up."
else
    wait $FORWARD4
    exit_status=$?
    echo "port-forward failed."
    exit $exit_status
fi

echo "Logs"
kubectl logs -n $NAMESPACE --max-log-requests=50 --selector=run=attested-hello-world-tls

mitigation="check that sleep time for establishing tunnel is sufficiently long."
EXPECTED='Hello World!
$GREETING is: hello from SCONE with encrypted source code and auto-generated certs!!!'
MSG=$(curl -k https://localhost:8084)
echo "Got message: $MSG"
mitigation="See error log above"

if [[ "$MSG" != "$EXPECTED" ]] ; then
    mitigation="Check that service actually runs."
    echo "Got wrong result: $MSG"
    echo "    and expected: $EXPECTED"
    exit 1
fi

echo "All tests were successful."
