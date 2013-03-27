module Pass
  module APIOperations
    module Create
      module ClassMethods
        def create(params={}, api_token=nil)
          response, api_token = Pass.request(:post, self.url, api_token, params)
          Util.convert_to_pass_object(response, api_token)
        end
      end

      def self.included(base)
        base.extend(ClassMethods)
      end
    end
  end
end