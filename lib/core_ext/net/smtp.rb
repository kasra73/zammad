# rubocop:disable all

require 'rubyntlm'

module Net
  class SMTP
    # true if server advertises AUTH NTLM.
    # You cannot get valid value before opening SMTP session.
    def capable_ntlm_auth?
      auth_capable?('NTLM')
    end

    def auth_ntlm(user, secret)
      check_auth_args user, secret
      res = critical {
        # send type1 message
        t1 = Net::NTLM::Message::Type1.new()
        t1.domain = user[/^[^\\]+/]
        @socket.writeline "AUTH NTLM " + t1.encode64

        # receive type2 message
        line = @socket.readline
        unless /334 (.+)/ =~ line
          raise RuntimeError, "SMTP AUTH don't recognize this: #{line}"
        end
        t2 = Net::NTLM::Message.decode64($1)

        # send Type3 Message
	      t3 = t2.response({:user => user[/[^\\]+$/], :password => secret}, {:ntlmv2 => true})
        get_response(t3.encode64)
      }
      check_auth_response res
      res
    end

    def do_start(helo_domain, user, secret, authtype)
      raise IOError, 'SMTP session already started' if @started
      if user or secret
        check_auth_method(authtype || DEFAULT_AUTH_TYPE)
        check_auth_args user, secret
      end
      s = Timeout.timeout(@open_timeout, Net::OpenTimeout) do
        tcp_socket(@address, @port)
      end
      logging "Connection opened: #{@address}:#{@port}"
      @socket = new_internet_message_io(tls? ? tlsconnect(s) : s)
      check_response critical { recv_response() }
      do_helo helo_domain
      if starttls_always? or (capable_starttls? and starttls_auto?)
        if !capable_starttls?
          raise SMTPUnsupportedCommand,
              "STARTTLS is not supported on this server"
        end
        starttls
        @socket = new_internet_message_io(tlsconnect(s))
        # helo response may be different after STARTTLS
        do_helo helo_domain
      end

      # ADD auto detection of authtype - https://github.com/zammad/zammad/issues/240
      # set detected authtype based on smtp server capabilities
      if user or secret
        if !authtype
          if auth_capable?(DEFAULT_AUTH_TYPE)
            authtype = DEFAULT_AUTH_TYPE
          elsif capable_plain_auth?
            authtype = 'PLAIN'
          elsif capable_login_auth?
            authtype = 'LOGIN'
          elsif capable_cram_md5_auth?
            authtype = 'CRAM-MD5'
          elsif capable_ntlm_auth?
            authtype = 'NTLM'
          end
        end
      end
      # /ADD auto detection of authtype - https://github.com/zammad/zammad/issues/240

      authenticate user, secret, (authtype || DEFAULT_AUTH_TYPE) if user
      @started = true
    ensure
      if !@started
        # authentication failed, cancel connection.
        s.close if s and not s.closed?
        @socket = nil
      end
    end
  end
end
# rubocop:enable all