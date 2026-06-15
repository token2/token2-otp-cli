import subprocess
import sys
 
# Replace "app.py" with the correct script name
subprocess.Popen([sys.executable, "app.py"] + sys.argv[1:])

# Print the arguments before the pause
#print("Arguments:", " ".join(sys.argv[1:]))

# Add a pause to keep the window open
 
input("This OTP profile is protected\r\nyou need to touch the button on the device to show the OTP\r\nPress Enter to exit...\r\n")
 