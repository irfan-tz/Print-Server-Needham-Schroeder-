make clean
make
mkdir -p temp

# Kill existing instances to prevent address conflicts
pkill kdc || true
pkill prnsrv || true

# Start KDC and print server
./kdc &
KDC_PID=$!

./prnsrv &
PRNSRV_PID=$!

# Allow servers to initialize
sleep 2

# Run the client
./client ALICE password send.txt

# Cleanup
kill $KDC_PID $PRNSRV_PID
wait $KDC_PID $PRNSRV_PID 2>/dev/null
rm -f *_input_* *_output_* *_temp_*