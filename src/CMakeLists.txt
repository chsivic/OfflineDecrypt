include_directories(${OfflineDecrypt_SOURCE_DIR}/inc)
add_executable(OfflineDecrypt OfflineDecrypt.c)
# set the path to the library folder
#link_directories(/usr/lib)
target_link_libraries(OfflineDecrypt ssl crypto pcap)
install(TARGETS OfflineDecrypt DESTINATION ${OfflineDecrypt_SOURCE_DIR}/bin)
