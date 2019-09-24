#!/bin/bash
echo "Build SecureFetch...\n"
cmake ..
make

#copy created binary
if [ -e ./SecureFetch.exe ]
then
  cp ./SecureFetch.exe ../../../native_dist/win/SecureFetch.exe
  rm ./SecureFetch.exe
  echo "[INFO]: ...moved SecureFetch.exe\n"

elif [ -e ./SecureFetch ]
then
  cp ./SecureFetch ../../../native_dist/gnu/SecureFetch
  rm ./SecureFetch
  echo "[INFO]: ...moved SecureFetch"

else
  echo "[Error]: ...SecureFetch/SecureFetch.exe could not be built or found!\n"

fi

# clean build directory
rm -r ./CMakeFiles/
rm ./CMakeCache.txt
rm ./cmake_install.cmake
rm ./Makefile
echo "[INFO]: ...cleaned Build directory"
echo "[INFO]: ...finished"
