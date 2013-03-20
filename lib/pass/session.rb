module Pass
  class Session < APIResource
    include Stripe::APIOperations::Create
    
  end
end