import sys
import struct
import plugin_api_pb2

def main():
    while True:
        # Read length (4 bytes big endian)
        try:
            len_bytes = sys.stdin.buffer.read(4)
            if not len_bytes:
                break
            msg_len = struct.unpack('>I', len_bytes)[0]
            
            # Read protobuf message
            msg_bytes = sys.stdin.buffer.read(msg_len)
            if not msg_bytes:
                break
                
            request = plugin_api_pb2.PluginParseRequest()
            request.ParseFromString(msg_bytes)
            
            # Simple "Decoding" logic
            response = plugin_api_pb2.PluginParseResponse()
            response.success = True
            response.name = "ExamplePlugin"
            
            # Decode payload as string for demo
            try:
                payload_str = request.payload.decode('utf-8', errors='ignore')
                response.attributes["payload_string"] = payload_str
                response.attributes["src"] = f"{request.src_ip}:{request.src_port}"
            except Exception as e:
                response.success = False
                response.error_message = str(e)
            
            # Serialize response
            resp_bytes = response.SerializeToString()
            resp_len = len(resp_bytes)
            
            # Write length + response
            sys.stdout.buffer.write(struct.pack('>I', resp_len))
            sys.stdout.buffer.write(resp_bytes)
            sys.stdout.buffer.flush()
            
        except Exception as e:
            sys.stderr.write(f"Plugin Error: {e}\n")
            break

if __name__ == "__main__":
    main()
