import subprocess
import sys

def generate():
    subprocess.check_call([
        sys.executable, "-m", "grpc_tools.protoc",
        "-I../../proto",
        "--python_out=.",
        "../../proto/packetrecorder/v1/plugin_api.proto"
    ])

if __name__ == "__main__":
    generate()
