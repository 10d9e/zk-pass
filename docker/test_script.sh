#!/bin/bash

# Function to run a single test scenario
run_test() {
    local type=$1
    local curve=$2
    local modp=$3

    echo "Testing configuration: type=$type, curve=$curve, modp=$modp"

    # Start the server with the specified configuration
    /usr/local/bin/server --host 0.0.0.0 --type "$type" --curve "$curve" --modp "$modp" &
    SERVER_PID=$!

    # Give the server some time to start
    sleep 2

    # Run the client with the same configuration
    /usr/local/bin/client --host 0.0.0.0 --type "$type" --curve "$curve" --modp "$modp"

    # Capture the client's exit code
    CLIENT_EXIT_CODE=$?

    # Kill the server process
    kill $SERVER_PID

    # Validate the client's exit code (assuming 0 indicates success)
    if [ $CLIENT_EXIT_CODE -ne 0 ]; then
        echo "Test failed for configuration: type=$type, curve=$curve, modp=$modp"
        exit 1
    fi

    echo "Test passed for configuration: type=$type, curve=$curve, modp=$modp"
}

# Test scenarios
run_test "discrete_log" "ec25519" "rfc5114_modp_1024_160"
run_test "discrete_log" "ec25519" "rfc5114_modp_2048_224"
run_test "discrete_log" "ec25519" "rfc5114_modp_1024_160"
run_test "elliptic_curve" "ec25519" "rfc5114_modp_2048_256"
# Add more test scenarios as needed

echo "All tests passed successfully!"
