# Pass Ruby API

require 'cgi'
require 'set'
require 'openssl'
require 'rest_client'
require 'multi_json'

# Version
require 'pass/version'

# API operations
require 'pass/api_operations/create'

# API
require 'pass/util'
require 'pass/json'
require 'pass/pass_object'
require 'pass/api_resource'
require 'pass/session'

# Errors
require 'pass/errors/pass_error'
require 'pass/errors/api_error'
require 'pass/errors/api_connection_error'
require 'pass/errors/invalid_request_error'
require 'pass/errors/authentication_error'

module Pass
  @@ssl_bundle_path = File.join(File.dirname(__FILE__), 'data/ca-certificates.crt')
  @@api_token = nil
  @@api_base = 'http://api.service.localhost:3000'
  @@verify_ssl_certs = true
  @@api_version = nil

  def self.api_url(url='')
    @@api_base + url
  end

  def self.api_token=(api_token)
    @@api_token = api_token
  end

  def self.api_token
    @@api_token
  end

  def self.api_base=(api_base)
    @@api_base = api_base
  end

  def self.api_base
    @@api_base
  end

  def self.verify_ssl_certs=(verify)
    @@verify_ssl_certs = verify
  end

  def self.verify_ssl_certs
    @@verify_ssl_certs
  end

  def self.api_version=(version)
    @@api_version = version
  end

  def self.api_version
    @@api_version
  end

  def self.request(method, url, api_token, params={}, headers={})
    api_token ||= @@api_token
    raise AuthenticationError.new('No API token provided.  (HINT: set your API token using "Pass.api_token = <API-TOKEN>".') unless api_token

    if !verify_ssl_certs
      unless @no_verify
        $stderr.puts "WARNING: Running without SSL cert verification.  Execute 'Pass.verify_ssl_certs = true' to enable verification."
        @no_verify = true
      end
      ssl_opts = { :verify_ssl => false }
    elsif !Util.file_readable(@@ssl_bundle_path)
      unless @no_bundle
        $stderr.puts "WARNING: Running without SSL cert verification because #{@@ssl_bundle_path} isn't readable"
        @no_bundle = true
      end
      ssl_opts = { :verify_ssl => false }
    else
      ssl_opts = {
        :verify_ssl => OpenSSL::SSL::VERIFY_PEER,
        :ssl_ca_file => @@ssl_bundle_path
      }
    end
    uname = (@@uname ||= RUBY_PLATFORM =~ /linux|darwin/i ? `uname -a 2>/dev/null`.strip : nil)
    lang_version = "#{RUBY_VERSION} p#{RUBY_PATCHLEVEL} (#{RUBY_RELEASE_DATE})"
    ua = {
      :bindings_version => Pass::VERSION,
      :lang => 'ruby',
      :lang_version => lang_version,
      :platform => RUBY_PLATFORM,
      :publisher => 'pass',
      :uname => uname
    }

    params = Util.objects_to_ids(params)
    url = self.api_url(url)
    case method.to_s.downcase.to_sym
    when :get, :head, :delete
      # Make params into GET parameters
      if params && params.count > 0
        query_string = Util.flatten_params(params).collect{|key, value| "#{key}=#{Util.url_encode(value)}"}.join('&')
        url += "#{URI.parse(url).query ? '&' : '?'}#{query_string}"
      end
      payload = nil
    else
      payload = Util.flatten_params(params).collect{|(key, value)| "#{key}=#{Util.url_encode(value)}"}.join('&')
    end

    begin
      headers = { :x_pass_client_user_agent => Pass::JSON.dump(ua) }.merge(headers)
    rescue => e
      headers = {
        :x_pass_client_raw_user_agent => ua.inspect,
        :error => "#{e} (#{e.class})"
      }.merge(headers)
    end

    headers = {
      :user_agent => "Pass/v1 RubyBindings/#{Pass::VERSION}",
      :authorization => "Token #{api_token}",
      :content_type => 'application/x-www-form-urlencoded',
      :accept => 'application/vnd.pass.v1'
    }.merge(headers)

    if self.api_version
      headers[:pass_version] = self.api_version
    end

    opts = {
      :method => method,
      :url => url,
      :headers => headers,
      :open_timeout => 30,
      :payload => payload,
      :timeout => 80
    }.merge(ssl_opts)

    begin
      response = execute_request(opts)
    rescue SocketError => e
      self.handle_restclient_error(e)
    rescue NoMethodError => e
      # Work around RestClient bug
      if e.message =~ /\WRequestFailed\W/
        e = APIConnectionError.new('Unexpected HTTP response code')
        self.handle_restclient_error(e)
      else
        raise
      end
    rescue RestClient::ExceptionWithResponse => e
      if rcode = e.http_code and rbody = e.http_body
        self.handle_api_error(rcode, rbody)
      else
        self.handle_restclient_error(e)
      end
    rescue RestClient::Exception, Errno::ECONNREFUSED => e
      self.handle_restclient_error(e)
    end

    rbody = response.body
    rcode = response.code
    begin
      # Would use :symbolize_names => true, but apparently there is
      # some library out there that makes symbolize_names not work.
      resp = Pass::JSON.load(rbody)
    rescue MultiJson::DecodeError
      raise APIError.new("Invalid response object from API: #{rbody.inspect} (HTTP response code was #{rcode})", rcode, rbody)
    end

    resp = Util.symbolize_names(resp)
    [resp, api_token]
  end

  private

  def self.execute_request(opts)
    RestClient::Request.execute(opts)
  end

  def self.handle_api_error(rcode, rbody)
    begin
      error_obj = Pass::JSON.load(rbody)
      error_obj = Util.symbolize_names(error_obj)
      error = error_obj[:error] or raise PassError.new # escape from parsing
    rescue MultiJson::DecodeError, PassError
      raise APIError.new("Invalid response object from API: #{rbody.inspect} (HTTP response code was #{rcode})", rcode, rbody)
    end

    case rcode
    when 400, 404 then
      raise invalid_request_error(error, rcode, rbody, error_obj)
    when 401
      raise authentication_error(error, rcode, rbody, error_obj)
    when 402
      raise invalid_request_error(error, rcode, rbody, error_obj)
    else
      raise api_error(error, rcode, rbody, error_obj)
    end
  end

  def self.invalid_request_error(error, rcode, rbody, error_obj)
    InvalidRequestError.new(error[:message], error[:param], rcode, rbody, error_obj)
  end

  def self.authentication_error(error, rcode, rbody, error_obj)
    AuthenticationError.new(error[:message], rcode, rbody, error_obj)
  end

  def self.card_error(error, rcode, rbody, error_obj)
    CardError.new(error[:message], error[:param], error[:code], rcode, rbody, error_obj)
  end

  def self.api_error(error, rcode, rbody, error_obj)
    APIError.new(error[:message], rcode, rbody, error_obj)
  end

  def self.handle_restclient_error(e)
    case e
    when RestClient::ServerBrokeConnection, RestClient::RequestTimeout
      message = "Could not connect to Pass (#{@@api_base}).  Please check your internet connection and try again.  If this problem persists, you should check Pass's service status at https://twitter.com/passstatus, or let us know at support@passauth.net."
    when RestClient::SSLCertificateNotVerified
      message = "Could not verify Pass's SSL certificate.  Please make sure that your network is not intercepting certificates.  (Try going to https://api.passauth.net/v1 in your browser.)  If this problem persists, let us know at support@passauth.net."
    when SocketError
      message = "Unexpected error communicating when trying to connect to Pass.  HINT: You may be seeing this message because your DNS is not working.  To check, try running 'host passauth.net' from the command line."
    else
      message = "Unexpected error communicating with Pass. If this problem persists, let us know at support@passauth.net."
    end
    message += "\n\n(Network error: #{e.message})"
    raise APIConnectionError.new(message)
  end

end