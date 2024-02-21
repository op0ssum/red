#!/bin/bash
# run in webroot - cred: lazy website cloning, https://gist.github.com/Mr-Un1k0d3r/11bf902555d401c92c2e1b766275e6a2
echo "Cloning $1"
wget $1 -O index.html &> /dev/null
TAG="<base href=\"$1\"/></head>"
sed '/<\/head>/i\'"$TAG" index.html | tee index.html &> /dev/null
echo "index.html was saved and modified"
