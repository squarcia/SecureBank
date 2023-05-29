cmake_minimum_required(VERSION 3.0)
project(SecureBank)

set(CMAKE_C_STANDARD 11)

# Imposta le opzioni di compilazione per OpenSSL
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I/opt/homebrew/opt/openssl@3/include")
set(ENV{LD_LIBRARY_PATH} "/opt/homebrew/opt/openssl@3/lib")

# Aggiungi il primo file sorgente al progetto
add_executable(ds server/ds.c)

# Aggiungi il secondo file sorgente al progetto
add_executable(client client/client.c)

# Collega le librerie di OpenSSL
find_library(SSL_LIBRARY ssl HINTS "/opt/homebrew/opt/openssl@3/lib" NO_DEFAULT_PATH)
find_library(CRYPTO_LIBRARY crypto HINTS "/opt/homebrew/opt/openssl@3/lib" NO_DEFAULT_PATH)

target_link_libraries(ds ${SSL_LIBRARY} ${CRYPTO_LIBRARY})
target_link_libraries(client ${SSL_LIBRARY} ${CRYPTO_LIBRARY})