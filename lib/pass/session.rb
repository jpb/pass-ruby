module Pass
  class Session
    def create(params={}, api_key=nil)
      response, api_key = Stripe.request(:post, self.url, api_key, params)
      Util.convert_to_stripe_object(response, api_key)
    end
  end
end