module Pass
  module APIOperations
    module List
      module ClassMethods
        def all(filters={}, api_token=nil)
          response, api_token = Pass.request(:get, url, api_token, filters)
          Util.convert_to_pass_object(response, api_token)
        end
      end

      def self.included(base)
        base.extend(ClassMethods)
      end
    end
  end
end