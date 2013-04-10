module Pass
  class Session < APIResource
    include Pass::APIOperations::Create
    include Pass::APIOperations::List

  end
end