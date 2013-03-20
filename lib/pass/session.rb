module Pass
  class Session
    def create(params={}, api_key=nil)
      response, api_key = Pass.request(:post, self.url, api_key, params)
      Util.convert_to_pass_object(response, api_key)
    end
  end
end