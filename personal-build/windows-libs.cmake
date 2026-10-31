# libuv >= 1.53 uses WaitOnAddress/WakeByAddressSingle on Windows.
# Upstream XMRig's FindUV.cmake does not import libuv's transitive link targets.
cmake_language(DEFER CALL target_link_libraries xmrig synchronization)
