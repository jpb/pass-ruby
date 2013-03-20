# Pass Ruby API

require 'cgi'
require 'set'
require 'openssl'
require 'rest_client'
require 'multi_json'

# Version
require 'pass/version'

# API
require 'pass/util'
require 'pass/json'
require 'pass/stripe_object'
require 'pass/api_resource'
require 'pass/session'

# Errors
require 'pass/errors/pass_error'
require 'pass/errors/api_error'
require 'pass/errors/api_connection_error'
require 'pass/errors/card_error'
require 'pass/errors/invalid_request_error'
require 'pass/errors/authentication_error'

module Pass
  @@ssl_bundle_path = File.join(File.dirname(__FILE__), 'data/ca-certificates.crt')
  @@api_key = nil
  @@api_base = 'http://api.pass-server.dev'
  @@verify_ssl_certs = true
  @@api_version = nil

  def self.api_url(url='')
    @@api_base + url
  end

  def self.api_key=(api_key)
    @@api_key = api_key
  end

  def self.api_key
    @@api_key
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

  def self.request(method, url, api_key, params={}, headers={})
    api_key ||= @@api_key
    raise AuthenticationError.new('No API key provided.  (HINT: set your API key using "Pass.api_key = <API-KEY>".') unless api_key

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
      :authorization => "Bearer #{api_key}",
      :content_type => 'application/x-www-form-urlencoded'
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
    [resp, api_key]
  end



end