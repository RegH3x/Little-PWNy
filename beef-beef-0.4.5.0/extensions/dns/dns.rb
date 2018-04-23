#
# Copyright (c) 2006-2013 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - http://beefproject.com
# See the file 'doc/COPYING' for copying permission
#
module BeEF
  module Extension
    module Dns

      # This class is responsible for providing a DNS nameserver that can be dynamically
      # configured by other modules and extensions. It is particularly useful for
      # performing DNS spoofing, hijacking, tunneling, etc.
      #
      # Only a single instance will exist during runtime (known as the "singleton pattern").
      # This makes it easier to coordinate actions across the various BeEF systems.
      class Server

        include Singleton

        attr_reader :address, :port

        # @!method self.instance
        #  Returns the singleton instance. Use this in place of {#initialize}.

        # @note This method cannot be invoked! Use {.instance} instead.
        # @see ::instance
        def initialize
          @lock = Mutex.new
          @server = nil
        end

        def set_server(server)
          @server = server
        end

        def get_server
          @server
        end

        # Starts the main DNS server run-loop in a new thread.
        #
        # @param address [String] interface address server should run on
        # @param port [Integer] desired server port number
        def run_server(address = '0.0.0.0', port = 5300)
          @address = address
          @port = port
            Thread.new do
              sleep(2)

              # antisnatchor: RubyDNS is already implemented with EventMachine 
              run_server_block(@address, @port)
            end
        end

        # Adds a new DNS rule or "resource record". Does nothing if rule is already present.
        #
        # @example Adds an A record for foobar.com with the value 1.2.3.4
        #
        #   dns = BeEF::Extension::Dns::Server.instance
        #
        #   id = dns.add_rule('foobar.com', Resolv::DNS::Resource::IN::A) do |transaction|
        #     transaction.respond!('1.2.3.4')
        #   end
        #
        # @param pattern [String, Regexp] query pattern to recognize
        # @param type [Resolv::DNS::Resource::IN] resource record type (e.g. A, CNAME, NS, etc.)
        #
        # @note When parameter 'pattern' is a literal Regexp object, it must NOT be passed
        #       using the /.../ literal syntax. Instead use either %r{...} or Regexp::new.
        #       This does not apply if 'pattern' is a variable.
        #
        # @yield callback to invoke when pattern is matched
        # @yieldparam transaction [RubyDNS::Transaction] details of query question and response
        #
        # @return [String] unique 7-digit hex identifier for use with {#remove_rule}
        #
        # @see #remove_rule
        # @see http://rubydoc.info/gems/rubydns/RubyDNS/Transaction
        def add_rule(pattern, type, &block)
          @lock.synchronize { @server.match(pattern, type, block) }
        end

        # Removes the given DNS rule. Any future queries for it will be passed through.
        #
        # @param id [Integer] id returned from {#add_rule}
        #
        # @return [Boolean] true on success, false on failure
        #
        # @see #add_rule
        def remove_rule(id)
          @lock.synchronize { @server.remove_rule(id) }
        end

        # Retrieves a specific rule given its id
        #
        # @param id [Integer] unique identifier for rule
        #
        # @return [Hash] hash representation of rule
        def get_rule(id)
          @lock.synchronize { @server.get_rule(id) }
        end

        # Returns an AoH representing the entire current DNS ruleset.
        #
        # Each element is a hash with the following keys:
        #
        # * <code>:id</code>
        # * <code>:pattern</code>
        # * <code>:type</code>
        # * <code>:response</code>
        #
        # @return [Array<Hash>] DNS ruleset (empty if no rules are currently loaded)
        def get_ruleset
          @lock.synchronize { @server.get_ruleset }
        end

        # Clears the entire DNS ruleset.
        #
        # Requests made after doing so will be passed through to the root nameservers.
        #
        # @return [Boolean] true on success, false on failure
        def remove_ruleset
          @lock.synchronize { @server.remove_ruleset }
        end

        private

        # Common code needed by {#run_server} to start DNS server.
        #
        # @param address [String] interface address server should run on
        # @param port [Integer] desired server port number
        def run_server_block(address, port)
          RubyDNS.run_server(:listen => [[:udp, address, port]]) do
            # Pass unmatched queries upstream to root nameservers
            dns_config = BeEF::Core::Configuration.instance.get('beef.extension.dns')
            unless dns_config['upstream'].nil?
              dns_config['upstream'].each do |server|
                if server[1].nil? or server[2].nil?
                  print_error "Invalid server '#{server[1]}:#{server[2]}' specified for upstream DNS server."
                  next
                elsif server[0] == 'tcp'
                  servers << [:tcp, server[1], server[2]]
                elsif server[0] == 'udp'
                  servers << [:udp, server[1], server[2]]
                else
                  print_error "Invalid protocol '#{server[0]}' specified for upstream DNS server."
                end
              end
            end
            if servers.empty?
              print_debug "No upstream DNS servers specified. Using '8.8.8.8'"
              servers << [:tcp, '8.8.8.8', 53]
              servers << [:udp, '8.8.8.8', 53]
            end
            otherwise do |transaction|
              transaction.passthrough!(
                  RubyDNS::Resolver.new servers
              )
            end
          end
        end

      end

    end
  end
end
