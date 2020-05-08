#!/bin/sh
goRoot=$(go env GOROOT)
goHostOS=$(go env GOHOSTOS)
goHostArch=$(go env GOHOSTARCH)
installRace=$(go env CGO_ENABLED)

localGoRoot="$1"
if [ -z "$localGoRoot" ]; then
  localGoRoot="./.GOROOT"
fi

patchSrc="./.patch/src"

mkdir -p ${localGoRoot}

#Setting up bin
if [ ! -d ${localGoRoot}/bin ]; then
	ln -s ${goRoot}/bin ${localGoRoot}/bin
fi

#src + patch
cp -r ${goRoot}/src ${localGoRoot}/
rm -rf ${localGoRoot}/src/crypto/tls #Should be fully rebuilt

#patching src
cp -rf ${patchSrc}/* ${localGoRoot}/src/

#pkg:
mkdir -p ${localGoRoot}/pkg
cp -rf ${goRoot}/pkg/${goHostOS}_${goHostArch} ${localGoRoot}/pkg/

#Removing outdated object files to be rebuilt
rm -rf ${localGoRoot}/pkg/${goHostOS}_${goHostArch}/crypto/tls.a
rm -rf ${localGoRoot}/pkg/${goHostOS}_${goHostArch}/net/http*

if [ $installRace -eq "1" ]; then
  if [ -d "${goRoot}/pkg/${goHostOS}_${goHostArch}_race" ]; then
	  cp -rf ${goRoot}/pkg/${goHostOS}_${goHostArch}_race ${localGoRoot}/pkg/
	fi
	rm -rf ${localGoRoot}/pkg/${goHostOS}_${goHostArch}_race/crypto/tls.a
	rm -rf ${localGoRoot}/pkg/${goHostOS}_${goHostArch}_race/net/http*
fi

if [ ! -d ${localGoRoot}/pkg/include ]; then
	ln -s ${goRoot}/pkg/include ${localGoRoot}/pkg/include
fi

if [ ! -d ${localGoRoot}/pkg/tool ]; then
	ln -s ${goRoot}/pkg/tool ${localGoRoot}/pkg/tool
	#cp -rf ${goRoot}/pkg/tool ${localGoRoot}/pkg/
fi