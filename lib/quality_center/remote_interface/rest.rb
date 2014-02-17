require 'httparty'
require 'logger'
require 'active_support/core_ext/hash'
require 'qa/quality_center/constants'
require 'qa/quality_center/remote_interface/exceptions'
require 'qa/quality_center/remote_interface/generic_entity_parser'

module QualityCenter
  module RemoteInterface

    # Wraps the QC Restful API.
    # qualitycenter:8080/qcbin/Help/doc_library/api_refs/REST/webframe.html
    # 
    # user     - Login username
    # password - Login password
    # logger   - A Logger to write HTTP calls to (optional)
    #
    # Example
    #
    #   connection = Rest.new(user:'user', password:'secret')
    #   connection.login
    #   defects = connection.defects
    class Rest

      include HTTParty
      include GenericEntityParser

      base_uri BASE_URI
     
      # User / Pass required, logger optional.  Initialize a blank cookie.
      def initialize(opts={})
        raise ArgumentError.new('No User/Pass') unless opts[:user] && opts[:password]
        raise ArgumentError.new('No Domain/Project') unless opts[:domain] && opts[:project]

        @logger = opts[:logger] || Logger.new(STDOUT)
        @login  = { :j_username => opts[:user], :j_password => opts[:password] }
        @cookie = ''
        @domain = opts[:domain]
        @project = opts[:project]
      end

      # Log in to the QC server using the credentials set at initialization.
      # This uses the 'user-facing' login page, due to problems with the method at
      # qualitycenter:8080/qcbin/Help/doc_library/api_refs/REST/Content/General/Authenticate.html
      #
      # Returns self if the login is successful.
      # Raises LoginError if the credentials were not accepted.
      def login(return_response=false)
        response = self.class.get(AUTH_URI[:get]).log(@logger)
        response = self.class.post(
          AUTH_URI[:post],
          body:    @login,
          headers: {'Cookie' => response.headers['Set-Cookie']}
        ).log(@logger)
        raise LoginError, "Bad credentials" if response.request.uri.to_s =~ /error/

        @cookie = response.request.options[:headers]['Cookie']
        return_response ? response : self
      end

      # Retrieve the contents of a path, respecting authentication cookies.
      # 
      # path - The url fragment to fetch.  Will be concatenated with PREFIX
      # opts - :prefix - The string to prepend to the path
      #                  default: PREFIX
      #        :raw    - Whether to return unprocessed raw XML, or a parsed hash
      #                  default: false
      # Examples
      #
      #   auth_get '/entities'
      #   # => (array of Entity hashes)
      #
      #   auth_get '/somethings', raw:true
      #   # => "<xml><somethings></somethings></xml>"
      #
      # Returns a hash or string representing the requested resource.
      def auth_get(path,opts={})
        opts.reverse_merge!(prefix:PREFIX, raw:false)
        url = opts[:prefix] + path
        assert_valid(res = stateful_get(url,opts) )

        # return raw xml if caller wants it,    otherwise a hash.
        return opts[:raw] ? res.response.body : res.parsed_response
      end

      # Post the contents of a path, respecting authentication cookies.
      # 
      # path - The url fragment to post.  Will be concatenated with PREFIX
      # opts - :prefix - The string to prepend to the path
      #                  default: PREFIX
      #        :raw    - Whether to return unprocessed raw XML, or a parsed hash
      #                  default: false
      #        :body   - The XML content to post
      # Examples
      #
      #   auth_post '/entities', body:<MyData>
      #   # => (array of Entity hashes)
      #
      #   auth_get '/somethings', raw:true
      #   # => "<xml><somethings></somethings></xml>"
      #
      # Returns a hash or string representing the requested resource.
      def auth_post(path,opts={})
        opts.reverse_merge!(prefix:PREFIX, raw:false)
        url = opts[:prefix] + path
        assert_valid(res = stateful_post(url,opts) )

        # return raw xml if caller wants it,    otherwise a hash.
        return opts[:raw] ? res.response.body : res.parsed_response
      end
      
      # The list of QC users.
      def users(opts={})
        @users ||= scoped_get('/customization/users',opts)
      end

      # Is the current session authenticated?
      #
      # Returns a boolean indicating whether QC likes us.
      def authenticated?
        return false if @cookie.empty?
        case self.class.get('/qcbin/rest/is-authenticated', headers: {'Cookie' => @cookie}).response.code
          when '200' then true
          else false
        end
      end

      # If someone asks for an entity we know about, handle it with the generic parser.
      def method_missing(meth, *args, &block)
        super unless ENTITIES.include?(meth.to_s)
        opts = args.first || {}
        generic_entity_fetch(meth,opts)
      end

      # Get a path scoped
      def scoped_get(path,opts={})
        auth_get(SCOPE % { :domain => @domain, :project => @project } + path, opts)
      end

      # Post a path scoped
      def scoped_post(path,opts={})
        auth_post(SCOPE % { :domain => @domain, :project => @project } + path, opts)
      end
      
      private

      # Check that a HTTP response is OK.
      def assert_valid(res)
        raise LoginError, res.code          if res.code == 401
        raise UnrecognizedResponse,res.code if res.code != 200 && res.code != 201
      end

      # Get somethig using the cookie
      def stateful_get(url,opts)
        raise NotAuthenticated if @cookie.empty?

        # Only pass in the query option if a query was given
        get_opts         = {headers: {'Cookie' => @cookie}}
        get_opts[:query] = opts[:query].to_hash unless opts[:query].empty?

        self.class.get(url, get_opts).log(@logger)
      end
      
      # Post somethig using the cookie
      def stateful_post(url,opts)
        raise NotAuthenticated if @cookie.empty?
        raise NoDataToPost unless opts[:body]

        self.class.post(
          url,
          body:    opts[:body],
          headers: {'Cookie' => @cookie, 'Content-Type' => 'application/xml'}
        ).log(@logger)
      end
    end
  end
end

# Patch the Response class to make logging cleaner.
module HTTParty
  class Response
    def log(logger)
      logger.debug "#{request.http_method.const_get :METHOD} #{request.uri} #{response.code} #{response.message}"
      self
    end
  end
end

# Nil is empty.  Don't let anyone tell you different.
class NilClass
  def empty?
    true
  end
end

