#!/bin/sh
goVersion=$(go version| grep -Eo 'go[0-9]+\.[0-9]+')
goRoot=$(go env GOROOT)
goHostOS=$(go env GOHOSTOS)
goHostArch=$(go env GOHOSTARCH)
installRace=$(go env CGO_ENABLED)


localGoRoot="$1"
if [ -z "$localGoRoot" ]; then
  localGoRoot="./.GOROOT"
fi

echo "==============="
echo "Reporting variables:"
echo "goVersion => '$goVersion'"
echo "goRoot => '$goRoot'"
echo "goHostOS => '$goHostOS'"
echo "goHostArch => '$goHostArch'"
echo "installRace => '$installRace'"
echo "localGoRoot => '$localGoRoot'"
echo "==============="

if [ -d "$localGoRoot" ]; then
  rm -rf "$localGoRoot"
fi

patchSrc="./.patch/src"
if [ "$goVersion" == "go1.16" ]; then
 patchSrc="./.patch_1.16/src"
fi

mkdir -p ${localGoRoot}

#Setting up bin
echo "Setting up symlink to ${goRoot}/bin"
if [ ! -d ${localGoRoot}/bin ]; then
	ln -s ${goRoot}/bin ${localGoRoot}/bin
fi

#src + patch
echo "Copying up ${goRoot}/src to ${localGoRoot}/"
cp -r ${goRoot}/src ${localGoRoot}/
#ESNI changes primarily here:
rm -rf ${localGoRoot}/src/crypto/tls #Should be fully rebuilt

#patching src
echo "Patching '${localGoRoot}/src/' with '${patchSrc}/*'"
cp -rf ${patchSrc}/* ${localGoRoot}/src/

#pkg:
mkdir -p ${localGoRoot}/pkg
echo "Copying '${goRoot}/pkg/${goHostOS}_${goHostArch}' to '${localGoRoot}/pkg/'"
cp -rf ${goRoot}/pkg/${goHostOS}_${goHostArch} ${localGoRoot}/pkg/

#Removing outdated object files to be rebuilt
rm -rf ${localGoRoot}/pkg/${goHostOS}_${goHostArch}/crypto/tls.a
rm -rf ${localGoRoot}/pkg/${goHostOS}_${goHostArch}/net/http*

if [ $installRace -eq "1" ]; then
  if [ -d "${goRoot}/pkg/${goHostOS}_${goHostArch}_race" ]; then
    echo "Copying '${goRoot}/pkg/${goHostOS}_${goHostArch}_race' to '${localGoRoot}/pkg/'"
	  cp -rf ${goRoot}/pkg/${goHostOS}_${goHostArch}_race ${localGoRoot}/pkg/
	fi
	rm -rf ${localGoRoot}/pkg/${goHostOS}_${goHostArch}_race/crypto/tls.a
	rm -rf ${localGoRoot}/pkg/${goHostOS}_${goHostArch}_race/net/http*
fi

if [ ! -d ${localGoRoot}/pkg/include ]; then
  echo "Adding symlink to  '${localGoRoot}/pkg/include'"
	ln -s ${goRoot}/pkg/include ${localGoRoot}/pkg/include
fi

if [ ! -d ${localGoRoot}/pkg/tool ]; then
  echo "Adding symlink to  '${localGoRoot}/pkg/tool'"
	ln -s ${goRoot}/pkg/tool ${localGoRoot}/pkg/tool
	#cp -rf ${goRoot}/pkg/tool ${localGoRoot}/pkg/
fi