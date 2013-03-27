module Pass
  class APIResource < PassObject
    def self.class_name
      self.name.split('::')[-1]
    end

    def self.url()
      if self == APIResource
        raise NotImplementedError.new('APIResource is an abstract class.  You should perform actions on its subclasses (Charge, Customer, etc.)')
      end
      "/#{CGI.escape(class_name.downcase)}s"
    end

    def url
      unless id = self['id']
        raise InvalidRequestError.new("Could not determine which URL to request: #{self.class} instance has invalid ID: #{id.inspect}", 'id')
      end
      "#{self.class.url}/#{CGI.escape(id)}"
    end

    def refresh
      response, api_token = Pass.request(:get, url, @api_token, @retrieve_options)
      refresh_from(response, api_token)
      self
    end

    def self.retrieve(id, api_token=nil)
      instance = self.new(id, api_token)
      instance.refresh
      instance
    end
  end
end