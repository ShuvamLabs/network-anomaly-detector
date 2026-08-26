cmake_minimum_required(VERSION 3.10)
project(AnomalyCapturer)

# Force the compiler to use C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define your paths
set(NPCAP_SDK_DIR "C:/Npcap-SDK")
set(ONNX_DIR "C:/onnxruntime")

# 1. Define the executable first
add_executable(capturer main.cpp app.rc)

# 2. Add Include Directories (Modern Target-based approach)
target_include_directories(capturer PRIVATE 
    "${NPCAP_SDK_DIR}/Include"
    "${ONNX_DIR}/include"
)

# 3. Add Linker Directories
target_link_directories(capturer PRIVATE 
    "${NPCAP_SDK_DIR}/Lib/x64"
    "${ONNX_DIR}/lib"
)

# 4. Link the Libraries
target_link_libraries(capturer PRIVATE 
    wpcap 
    ws2_32 
    onnxruntime
)

# Automatically copy BOTH ONNX DLLs and the model to the build output directory
add_custom_command(TARGET capturer POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${ONNX_DIR}/lib/onnxruntime.dll"
    $<TARGET_FILE_DIR:capturer>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${ONNX_DIR}/lib/onnxruntime_providers_shared.dll"
    $<TARGET_FILE_DIR:capturer>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_SOURCE_DIR}/network_anomaly_detector.onnx"
    $<TARGET_FILE_DIR:capturer>
)