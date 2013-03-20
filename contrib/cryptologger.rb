require 'socket'
require 'openssl'

secret = 'ciaociao'
iv = ''
address = '127.0.0.1'
port  = 1717
algo = 'bf-cbc'

s = UDPSocket.new
s.bind(address, port)
cipher = OpenSSL::Cipher.new(algo)
cipher.decrypt
cipher.key = secret + ("\0" * (cipher.key_len - secret.length))
cipher.iv = iv + ("0" * (cipher.iv_len - iv.length))

loop do
  msg, sender = s.recvfrom(8192)
  cipher.reset
  begin
    puts cipher.update(msg) + cipher.final
  rescue
  end
end
